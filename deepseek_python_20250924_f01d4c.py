import requests
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import threading
import time
import os
import asyncio
from pyrogram import Client, filters
from pyrogram.types import Message
from pyromod import listen
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

session = requests.Session()

# Define URLs and headers
base_url = 'https://online.utkarsh.com/'
login_url = 'https://online.utkarsh.com/web/Auth/login'
tiles_data_url = 'https://online.utkarsh.com/web/Course/tiles_data'
layer_two_data_url = 'https://online.utkarsh.com/web/Course/get_layer_two_data'
meta_source_url = '/meta_distributer/on_request_meta_source'

# Configuration
API_URL = "https://application.utkarshapp.com/index.php/data_model"
COMMON_KEY = b"%!^F&^$)&^$&*$^&"
COMMON_IV = b"#*v$JvywJvyJDyvJ"
key_chars = "%!F*&^$)_*%3f&B+"
iv_chars = "#*$DJvyw2w%!_-$@"
HEADERS = {
    "Authorization": "Bearer 152#svf346t45ybrer34yredk76t",
    "Content-Type": "text/plain; charset=UTF-8",
    "devicetype": "1",
    "host": "application.utkarshapp.com",
    "lang": "1",
    "user-agent": "okhttp/4.9.0",
    "userid": "0",
    "version": "152"
}

# Bot Configuration
API_ID = 21179966
API_HASH = "d97919fb0a3c725e8bb2a25bbb37d57c"
BOT_TOKEN = "8379064968:AAE6H8ReO9byzujjWJbaYOz8SLbZL3uGt18"
ALLOWED_USER = 7326397503

# Initialize bot
bot = Client("utkarsh_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# Global variables for progress tracking
current_progress = {}
progress_lock = threading.Lock()

def update_progress(course_id, message):
    with progress_lock:
        current_progress[course_id] = message

def get_progress(course_id):
    with progress_lock:
        return current_progress.get(course_id, "Starting extraction...")

def handle_error(message, exception=None):
    error_msg = f"Error: {message}"
    if exception:
        error_msg += f"\nException: {exception}"
    logger.error(error_msg)
    return error_msg

# Encryption and Decryption Functions
def encrypt(data, use_common_key, key, iv):
    cipher_key, cipher_iv = (COMMON_KEY, COMMON_IV) if use_common_key else (key, iv)
    cipher = AES.new(cipher_key, AES.MODE_CBC, cipher_iv)
    padded_data = pad(json.dumps(data, separators=(",", ":")).encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return b64encode(encrypted).decode() + ":"

def decrypt(data, use_common_key, key, iv):
    cipher_key, cipher_iv = (COMMON_KEY, COMMON_IV) if use_common_key else (key, iv)
    cipher = AES.new(cipher_key, AES.MODE_CBC, cipher_iv)
    try:
        encrypted_data = b64decode(data.split(":")[0])
        decrypted_bytes = cipher.decrypt(encrypted_data)
        decrypted = unpad(decrypted_bytes, AES.block_size).decode()
        return decrypted
    except (ValueError, TypeError) as e:
        logger.error(f"Decryption error: {e}")
        return None

def post_request(path, data=None, use_common_key=False, key=None, iv=None):
    encrypted_data = encrypt(data, use_common_key, key, iv) if data else data
    response = requests.post(f"{API_URL}{path}", headers=HEADERS, data=encrypted_data)
    decrypted_data = decrypt(response.text, use_common_key, key, iv)
    if decrypted_data:
        try:
            return json.loads(decrypted_data)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decoding error: {e}")
    return {}

def decrypt_stream(enc):
    try:
        enc = b64decode(enc)
        key = '%!$!%_$&!%F)&^!^'.encode('utf-8')
        iv = '#*y*#2yJ*#$wJv*v'.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_bytes = cipher.decrypt(enc)

        try:
            plaintext = unpad(decrypted_bytes, AES.block_size).decode('utf-8')
        except Exception:
            plaintext = decrypted_bytes.decode('utf-8', errors='ignore')
        
        cleaned_json = ''
        for i in range(len(plaintext)):
            try:
                json.loads(plaintext[:i+1])
                cleaned_json = plaintext[:i+1]  
            except json.JSONDecodeError:
                continue
        final_brace_index = cleaned_json.rfind('}')
        if final_brace_index != -1:
            cleaned_json = cleaned_json[:final_brace_index + 1]

        return cleaned_json

    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return None

def decrypt_and_load_json(enc):
    decrypted_data = decrypt_stream(enc)
    try:
        return json.loads(decrypted_data) if decrypted_data else None
    except json.JSONDecodeError as e:
        logger.error(f"JSON decoding error: {e}")
        return None

def encrypt_stream(plain_text):
    try:
        key = '%!$!%_$&!%F)&^!^'.encode('utf-8')
        iv = '#*y*#2yJ*#$wJv*v'.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, iv)

        padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_text)

        return b64encode(encrypted).decode('utf-8')
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return None

def sanitize_filename(name):
    """Sanitize filename by removing invalid characters"""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        name = name.replace(char, '_')
    return name[:100]  # Limit filename length

async def extract_course_data(course_id, course_title=""):
    """Main extraction function with progress tracking"""
    start_time = time.time()
    output_filename = f"{sanitize_filename(course_title)}_{course_id}.txt" if course_title else f"batch_{course_id}.txt"
    
    try:
        update_progress(course_id, "🔄 Retrieving CSRF token...")
        
        # Step 1: Retrieve CSRF token
        r1 = session.get(base_url)
        csrf_token = r1.cookies.get('csrf_name')
        if not csrf_token:
            raise ValueError("CSRF token not found.")

        # Step 2: Login
        update_progress(course_id, "🔐 Logging in...")
        email = "9571484459"
        password = "kajukaju"
        d1 = {
            'csrf_name': csrf_token,
            'mobile': email,
            'url': '0',
            'password': password,
            'submit': 'LogIn',
            'device_token': 'null'
        }

        h = {
            'Host': 'online.utkarsh.com',
            'Sec-Ch-Ua': '"Chromium";v="119", "Not?A_Brand";v="24"',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
            'Sec-Ch-Ua-Mobile': '?0',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.199 Safari/537.36'
        }

        u2 = session.post(login_url, data=d1, headers=h).json()
        r2 = u2.get("response")
        dr1 = decrypt_and_load_json(r2)
        token = dr1.get("token")
        jwt = dr1.get("data", {}).get("jwt")

        h["token"] = token
        h["jwt"] = jwt
        HEADERS["jwt"] = jwt

        # Step 3: Retrieve User Profile
        update_progress(course_id, "📊 Getting user profile...")
        profile = post_request("/users/get_my_profile", use_common_key=True)
        user_id = profile["data"]["id"]
        HEADERS["userid"] = user_id

        key = "".join(key_chars[int(i)] for i in (user_id + "1524567456436545")[:16]).encode()
        iv = "".join(iv_chars[int(i)] for i in (user_id + "1524567456436545")[:16]).encode()

        # Step 4: Get course data
        update_progress(course_id, "📥 Fetching course information...")
        d3 = {
            "course_id": course_id,
            "revert_api": "1#0#0#1",
            "parent_id": 0,
            "tile_id": "15330",
            "layer": 1,
            "type": "course_combo"
        }

        encrypted = encrypt_stream(json.dumps(d3))
        d4 = {'tile_input': encrypted, 'csrf_name': csrf_token}
        u4 = session.post(tiles_data_url, headers=h, data=d4).json()
        r4 = u4.get("response")
        dr3 = decrypt_and_load_json(r4)

        if not dr3 or "data" not in dr3:
            raise ValueError("No course data found")

        # Process course data
        total_links = 0
        with open(output_filename, "w", encoding="utf-8") as f:
            for course_index, course in enumerate(dr3.get("data", [])):
                fi = course.get("id")
                tn = course.get("title", f"Course_{course_id}")
                binfo = course.get("segment_information", "")
                
                if not course_title:  # Use first course title for filename
                    output_filename = f"{sanitize_filename(tn)}_{course_id}.txt"
                    # Reopen with correct filename
                    f.close()
                    f = open(output_filename, "w", encoding="utf-8")

                update_progress(course_id, f"📚 Processing: {tn}")

                # Layer 1: Subjects
                d5 = {
                    "course_id": fi, "layer": 1, "page": 1, "parent_id": fi, 
                    "revert_api": "1#1#0#1", "tile_id": "0", "type": "content"
                }
                d6 = {'tile_input': encrypt_stream(json.dumps(d5)), 'csrf_name': csrf_token}
                dr4 = decrypt_and_load_json(session.post(tiles_data_url, headers=h, data=d6).json()["response"])

                if not dr4 or "data" not in dr4:
                    continue

                subjects = dr4["data"].get("list", [])
                
                for subject_index, subj in enumerate(subjects):
                    sfi = subj.get("id")
                    sfn = subj.get("title", "").strip().replace("\n", " ")
                    
                    update_progress(course_id, f"📘 Subject: {sfn} ({subject_index+1}/{len(subjects)})")

                    # Layer 2: Topics
                    d7 = {
                        "course_id": fi, "parent_id": fi, "layer": 2, "page": 1, 
                        "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, 
                        "topic_id": sfi, "type": "content"
                    }
                    d8 = {
                        'layer_two_input_data': base64.b64encode(json.dumps(d7).encode()).decode(), 
                        'csrf_name': csrf_token
                    }
                    dr5 = decrypt_and_load_json(session.post(layer_two_data_url, headers=h, data=d8).json()["response"])

                    if not dr5 or "data" not in dr5:
                        continue

                    topics = dr5["data"].get("list", [])
                    
                    for topic_index, topic in enumerate(topics):
                        ti = topic.get("id")
                        tt = topic.get("title", "")

                        update_progress(course_id, f"📖 Topic: {tt}")

                        # Layer 3: Content
                        d9 = {
                            "course_id": fi, "parent_id": fi, "layer": 3, "page": 1, 
                            "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, 
                            "topic_id": ti, "type": "content"
                        }
                        d10 = {
                            'layer_two_input_data': base64.b64encode(json.dumps(d9).encode()).decode(), 
                            'csrf_name': csrf_token
                        }
                        dr6 = decrypt_and_load_json(session.post(layer_two_data_url, headers=h, data=d10).json()["response"])

                        if not dr6 or "data" not in dr6:
                            continue

                        content_items = dr6["data"].get("list", [])
                        
                        # Process content items in parallel for speed
                        with ThreadPoolExecutor(max_workers=10) as executor:
                            futures = []
                            
                            for item in content_items:
                                future = executor.submit(process_content_item, item, fi, sfn, key, iv)
                                futures.append(future)
                            
                            for future in as_completed(futures):
                                result = future.result()
                                if result:
                                    f.write(result + "\n")
                                    f.flush()  # Immediate write
                                    total_links += 1
                                    update_progress(course_id, f"✅ Extracted {total_links} links...")

        end_time = time.time()
        extraction_time = end_time - start_time
        
        # Clean up progress
        with progress_lock:
            if course_id in current_progress:
                del current_progress[course_id]
        
        return output_filename, total_links, extraction_time

    except Exception as e:
        # Clean up progress on error
        with progress_lock:
            if course_id in current_progress:
                del current_progress[course_id]
        raise e

def process_content_item(item, course_id, subject_name, key, iv):
    """Process individual content item and return link string"""
    try:
        item_id = item.get("id")
        item_title = item.get("title", "").replace("\n", " ").strip()
        tile_id = item.get("payload", {}).get("tile_id")
        
        if not all([item_id, item_title, tile_id]):
            return None

        payload = {
            "course_id": course_id,
            "device_id": "server_does_not_validate_it",
            "device_name": "server_does_not_validate_it",
            "download_click": "0",
            "name": f"{item_id}_0_0",
            "tile_id": tile_id,
            "type": "video"
        }
        
        response = post_request(meta_source_url, payload, key=key, iv=iv)
        data = response.get("data", {})
        
        # Extract URL
        url = extract_url_from_data(data)
        if url:
            return f"({subject_name}) | {item_title} : {url}"
            
    except Exception as e:
        logger.error(f"Error processing item {item.get('title', 'unknown')}: {e}")
    
    return None

def extract_url_from_data(data):
    """Extract URL from response data"""
    # Try bitrate URLs first
    urls = data.get("bitrate_urls", [])
    if isinstance(urls, list) and urls:
        for quality in urls:
            url = quality.get("url")
            if url:
                return url.split("?Expires=")[0]
    
    # Try direct link
    link = data.get("link", "")
    if link:
        if ".m3u8" in link or ".pdf" in link:
            return link.split("?Expires=")[0]
        elif "youtube.com" in link or "youtu.be" in link:
            return link
        else:
            return f"https://www.youtube.com/embed/{link}"
    
    return ""

# Bot Handlers
@bot.on_message(filters.command("start"))
async def start_handler(client: Client, message: Message):
    await message.reply(
        "👋 Welcome to the Utkarsh Extractor Bot!\n\n"
        "Use /utkarsh to begin extracting a course by batch ID.\n"
        "Made with ❤️ by x"
    )

@bot.on_message(filters.command("utkarsh") & filters.user(ALLOWED_USER))
async def extract_handler(client: Client, message: Message):
    try:
        # Ask for Batch ID
        ask_msg = await message.reply("👋 Hey I Am x\n\n📥 Please send the **Batch ID** to extract:")
        
        # Wait for response
        response = await client.listen(message.chat.id, timeout=120)
        course_id = response.text.strip()
        
        if not course_id.isdigit():
            await message.reply("❌ Invalid Batch ID. Please enter a numeric ID.")
            return

        # Start extraction
        status_msg = await message.reply("⚙️ Starting extraction... Please wait.")
        
        # Run extraction in background
        extraction_task = asyncio.create_task(
            run_extraction_with_progress(client, message, course_id, status_msg)
        )
        
    except asyncio.TimeoutError:
        await message.reply("⏰ Timeout! Please try again and respond faster.")
    except Exception as e:
        await message.reply(f"❌ Error: {str(e)}")

async def run_extraction_with_progress(client, message, course_id, status_msg):
    """Run extraction with progress updates"""
    try:
        # Start progress monitoring
        progress_task = asyncio.create_task(
            update_progress_message(client, status_msg, course_id)
        )
        
        # Run extraction
        result = await asyncio.get_event_loop().run_in_executor(
            None, extract_course_data, course_id
        )
        
        # Cancel progress updates
        progress_task.cancel()
        
        if result:
            filename, total_links, extraction_time = result
            
            # Send final result
            caption = (
                f"✅ Extraction Completed!\n\n"
                f"📊 Total Links: {total_links}\n"
                f"⏱️ Time Taken: {extraction_time:.2f} seconds\n"
                f"📁 File: {filename}"
            )
            
            await message.reply_document(
                document=filename,
                caption=caption
            )
            
            # Clean up file
            try:
                os.remove(filename)
            except:
                pass
                
        else:
            await message.reply("❌ Extraction failed. Please try again.")
            
    except Exception as e:
        error_msg = handle_error("Extraction failed", e)
        await message.reply(f"❌ {error_msg}")
        
        # Clean up progress
        with progress_lock:
            if course_id in current_progress:
                del current_progress[course_id]

async def update_progress_message(client, status_msg, course_id):
    """Update progress message every 5 seconds"""
    last_message = ""
    while True:
        try:
            current_progress_msg = get_progress(course_id)
            if current_progress_msg != last_message:
                await client.edit_message_text(
                    chat_id=status_msg.chat.id,
                    message_id=status_msg.id,
                    text=f"🔄 Extraction Progress:\n{current_progress_msg}"
                )
                last_message = current_progress_msg
            
            await asyncio.sleep(5)
        except:
            await asyncio.sleep(5)

@bot.on_message(filters.command("progress") & filters.user(ALLOWED_USER))
async def progress_handler(client: Client, message: Message):
    """Check current extraction progress"""
    try:
        # Extract course ID from message
        args = message.text.split()
        if len(args) < 2:
            await message.reply("Usage: /progress <course_id>")
            return
            
        course_id = args[1]
        progress = get_progress(course_id)
        await message.reply(f"📊 Current Progress for {course_id}:\n{progress}")
        
    except Exception as e:
        await message.reply(f"❌ Error checking progress: {str(e)}")

@bot.on_message(filters.command("cancel") & filters.user(ALLOWED_USER))
async def cancel_handler(client: Client, message: Message):
    """Cancel ongoing extraction"""
    try:
        args = message.text.split()
        if len(args) < 2:
            await message.reply("Usage: /cancel <course_id>")
            return
            
        course_id = args[1]
        with progress_lock:
            if course_id in current_progress:
                del current_progress[course_id]
                
        await message.reply(f"⏹️ Extraction cancelled for course {course_id}")
        
    except Exception as e:
        await message.reply(f"❌ Error cancelling extraction: {str(e)}")

if __name__ == "__main__":
    print("🤖 Bot is starting...")
    bot.run()