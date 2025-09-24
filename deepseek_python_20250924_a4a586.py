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

# Initialize session
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
API_ID = 24250238
API_HASH = "cb3f118ce5553dc140127647edcf3720"
BOT_TOKEN = "7511520910:AAFpmjNQZFCyqDILQV7GzLpnbxPZ4CEhXxw"
ALLOWED_USER = 6175650047

# Initialize bot
bot = Client("utkarsh_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# Define function to handle errors
def handle_error(message, exception=None):
    print(f"Error: {message}")
    if exception:
        print(f"Exception details: {exception}")

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
        print(f"Decryption error: {e}")
        return None

def post_request(path, data=None, use_common_key=False, key=None, iv=None):
    encrypted_data = encrypt(data, use_common_key, key, iv) if data else data
    response = requests.post(f"{API_URL}{path}", headers=HEADERS, data=encrypted_data)
    decrypted_data = decrypt(response.text, use_common_key, key, iv)
    if decrypted_data:
        try:
            return json.loads(decrypted_data)
        except json.JSONDecodeError as e:
            print(f"JSON decoding error: {e}")
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
        
        # Clean JSON
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
        print(f"Decryption error: {e}")
        return None

def decrypt_and_load_json(enc):
    decrypted_data = decrypt_stream(enc)
    try:
        return json.loads(decrypted_data) if decrypted_data else {}
    except json.JSONDecodeError as e:
        print(f"JSON decoding error: {e}")
        return {}

def encrypt_stream(plain_text):
    try:
        key = '%!$!%_$&!%F)&^!^'.encode('utf-8')
        iv = '#*y*#2yJ*#$wJv*v'.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, iv)

        padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_text)

        return b64encode(encrypted).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def sanitize_filename(name):
    """Sanitize filename by removing invalid characters"""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        name = name.replace(char, '_')
    return name[:100]  # Limit filename length

async def utk(course_id, message):
    """Main extraction function with progress updates"""
    progress_msg = None
    course_title = "Unknown_Course"
    
    try:
        # Step 1: Retrieve CSRF token
        await message.edit_text("🔄 Retrieving CSRF token...")
        r1 = session.get(base_url)
        csrf_token = r1.cookies.get('csrf_name')
        if not csrf_token:
            raise ValueError("CSRF token not found.")

        # Step 2: Login
        await message.edit_text("🔐 Logging in...")
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
        await message.edit_text("👤 Retrieving user profile...")
        profile = post_request("/users/get_my_profile", use_common_key=True)
        user_id = profile["data"]["id"]
        HEADERS["userid"] = user_id

        key = "".join(key_chars[int(i)] for i in (user_id + "1524567456436545")[:16]).encode()
        iv = "".join(iv_chars[int(i)] for i in (user_id + "1524567456436545")[:16]).encode()

        # Step 4: Get course data
        await message.edit_text("📚 Fetching course information...")
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

        if not dr3.get("data"):
            await message.edit_text("❌ No course data found. Invalid Batch ID?")
            return

        # Get course title for filename
        course = dr3["data"][0] if dr3["data"] else {}
        course_title = sanitize_filename(course.get("title", f"Batch_{course_id}"))
        filename = f"{course_title}_{course_id}.txt"

        # Initialize counters for progress
        total_subjects = 0
        total_topics = 0
        total_videos = 0
        processed_videos = 0

        # Count total items first for progress tracking
        await message.edit_text("📊 Counting total items...")
        for course_data in dr3.get("data", []):
            fi = course_data.get("id")
            
            # Count subjects
            d5 = {"course_id": fi, "layer": 1, "page": 1, "parent_id": fi, 
                  "revert_api": "1#1#0#1", "tile_id": "0", "type": "content"}
            d6 = {'tile_input': encrypt_stream(json.dumps(d5)), 'csrf_name': csrf_token}
            dr4 = decrypt_and_load_json(session.post(tiles_data_url, headers=h, data=d6).json()["response"])
            
            subjects = dr4.get("data", {}).get("list", [])
            total_subjects += len(subjects)
            
            for subject in subjects:
                sfi = subject.get("id")
                
                # Count topics
                d7 = {"course_id": fi, "parent_id": fi, "layer": 2, "page": 1, 
                      "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, 
                      "topic_id": sfi, "type": "content"}
                d8 = {'layer_two_input_data': base64.b64encode(json.dumps(d7).encode()).decode(), 
                      'csrf_name': csrf_token}
                dr5 = decrypt_and_load_json(session.post(layer_two_data_url, headers=h, data=d8).json()["response"])
                
                topics = dr5.get("data", {}).get("list", [])
                total_topics += len(topics)
                
                for topic in topics:
                    ti = topic.get("id")
                    
                    # Count videos
                    d9 = {"course_id": fi, "parent_id": fi, "layer": 3, "page": 1, 
                          "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, 
                          "topic_id": ti, "type": "content"}
                    d10 = {'layer_two_input_data': base64.b64encode(json.dumps(d9).encode()).decode(), 
                           'csrf_name': csrf_token}
                    dr6 = decrypt_and_load_json(session.post(layer_two_data_url, headers=h, data=d10).json()["response"])
                    
                    videos = dr6.get("data", {}).get("list", [])
                    total_videos += len(videos)

        await message.edit_text(f"📊 Found: {total_subjects} subjects, {total_topics} topics, {total_videos} videos")

        # Start extraction
        start_time = time.time()
        processed_videos = 0
        
        def process_video_item(video_item, fi, subject_name, key, iv):
            """Process a single video item and return formatted string"""
            nonlocal processed_videos
            try:
                ji = video_item.get("id")
                jt = video_item.get("title")
                jti = video_item["payload"]["tile_id"]
                j4 = {
                    "course_id": fi,
                    "device_id": "server_does_not_validate_it",
                    "device_name": "server_does_not_validate_it",
                    "download_click": "0",
                    "name": ji + "_0_0",
                    "tile_id": jti,
                    "type": "video"
                }
                j5 = post_request(meta_source_url, j4, key=key, iv=iv)
                cj = j5.get("data", {})
                
                # Extract URL
                urls = cj.get("bitrate_urls", [])
                link = ""
                if isinstance(urls, list) and urls:
                    for q in urls:
                        u = q.get("url")
                        if u:
                            link = u.split("?Expires=")[0]
                            break
                else:
                    vu = cj.get("link", "")
                    if vu:
                        if ".m3u8" in vu or ".pdf" in vu:
                            link = vu.split("?Expires=")[0]
                        elif ".ws" in vu and "https" in vu:
                            link = vu
                        else:
                            link = f"https://www.youtube.com/embed/{vu}"
                
                processed_videos += 1
                return f"({subject_name}) | {jt} : {link}" if link else None
                
            except Exception as e:
                print(f"⚠️ Video error: {video_item.get('title')} - {e}")
                return None

        # Main extraction loop
        with open(filename, "w", encoding='utf-8') as f:
            f.write(f"📦 Course: {course_title} (Batch ID: {course_id})\n")
            f.write("="*60 + "\n\n")
            
            for course_idx, course_data in enumerate(dr3.get("data", []), 1):
                fi = course_data.get("id")
                tn = course_data.get("title")
                binfo = course_data.get("segment_information", "")
                
                await message.edit_text(f"📚 Processing course {course_idx}: {tn}")
                
                # Get subjects
                d5 = {"course_id": fi, "layer": 1, "page": 1, "parent_id": fi, 
                      "revert_api": "1#1#0#1", "tile_id": "0", "type": "content"}
                d6 = {'tile_input': encrypt_stream(json.dumps(d5)), 'csrf_name': csrf_token}
                dr4 = decrypt_and_load_json(session.post(tiles_data_url, headers=h, data=d6).json()["response"])
                
                for subject_idx, subject in enumerate(dr4.get("data", {}).get("list", []), 1):
                    sfi = subject.get("id")
                    sfn = subject.get("title", "").strip().replace("\n", " ")
                    
                    await message.edit_text(
                        f"📘 Processing subject {subject_idx}/{total_subjects}: {sfn}\n"
                        f"📹 Videos processed: {processed_videos}/{total_videos}"
                    )
                    
                    # Get topics
                    d7 = {"course_id": fi, "parent_id": fi, "layer": 2, "page": 1, 
                          "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, 
                          "topic_id": sfi, "type": "content"}
                    d8 = {'layer_two_input_data': base64.b64encode(json.dumps(d7).encode()).decode(), 
                          'csrf_name': csrf_token}
                    dr5 = decrypt_and_load_json(session.post(layer_two_data_url, headers=h, data=d8).json()["response"])
                    
                    for topic_idx, topic in enumerate(dr5.get("data", {}).get("list", []), 1):
                        ti = topic.get("id")
                        tt = topic.get("title", "")
                        
                        # Get videos
                        d9 = {"course_id": fi, "parent_id": fi, "layer": 3, "page": 1, 
                              "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, 
                              "topic_id": ti, "type": "content"}
                        d10 = {'layer_two_input_data': base64.b64encode(json.dumps(d9).encode()).decode(), 
                               'csrf_name': csrf_token}
                        dr6 = decrypt_and_load_json(session.post(layer_two_data_url, headers=h, data=d10).json()["response"])
                        
                        video_items = dr6.get("data", {}).get("list", [])
                        
                        if video_items:
                            # Process videos in parallel with limited workers for stability
                            with ThreadPoolExecutor(max_workers=10) as executor:
                                futures = [
                                    executor.submit(process_video_item, v, fi, sfn, key, iv)
                                    for v in video_items
                                ]
                                
                                for future in as_completed(futures):
                                    result = future.result()
                                    if result:
                                        f.write(result + "\n")
                                        f.flush()  # Ensure immediate writing

        end_time = time.time()
        extraction_time = end_time - start_time
        
        # Final message
        await message.edit_text(
            f"✅ Extraction completed!\n\n"
            f"📊 Statistics:\n"
            f"• Subjects: {total_subjects}\n"
            f"• Topics: {total_topics}\n"
            f"• Videos/PDFs: {processed_videos}\n"
            f"⏱️ Time taken: {extraction_time:.2f} seconds\n"
            f"📁 File: {filename}"
        )
        
        return filename

    except Exception as e:
        await message.edit_text(f"❌ Error during extraction: {str(e)}")
        return None

# Bot Handlers
@bot.on_message(filters.command("start"))
async def start_handler(client: Client, message: Message):
    await message.reply(
        "👋 Welcome to the Utkarsh Extractor Bot!\n\n"
        "Use /utkarsh to begin extracting a course by batch ID.\n"
        "Made by x"
    )

@bot.on_message(filters.command("utkarsh"))
async def get_course_id(client: Client, message: Message):
    if message.from_user.id != ALLOWED_USER:
        await message.reply("❌ You are not authorized to use this bot.")
        return

    try:
        # Ask for Batch ID
        ask = await message.reply("👋 Hey I Am x\n\n📥 Please send the *Batch ID* to extract:")
        
        # Wait for response
        response = await bot.listen(message.chat.id, timeout=120)
        course_id = response.text.strip()
        
        # Create progress message
        progress_msg = await message.reply("⚙️ Starting extraction... Please wait.")
        
        # Run extraction
        filename = await utk(course_id, progress_msg)
        
        if filename and os.path.exists(filename):
            # Send result file
            await message.reply_document(
                filename, 
                caption=f"✅ Extraction completed for Batch ID: {course_id}"
            )
            # Clean up
            os.remove(filename)
        else:
            await message.reply("❌ Extraction failed or no data found.")
            
    except asyncio.TimeoutError:
        await message.reply("❌ Timeout: No response received within 2 minutes.")
    except Exception as e:
        await message.reply(f"❌ Error: {str(e)}")

# Start the bot
if __name__ == "__main__":
    print("🤖 Bot is starting...")
    bot.run()