# Install all required libraries for the bot to run correctly, including tgcrypto for speed
pip install pyrogram pyromod requests pycryptodome tgcrypto

# --- Your Bot Code Starts Here ---
import requests
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import asyncio
import os
import re
from io import StringIO
from pyrogram import Client, filters
from pyrogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton
from pyromod import listen # <--- YEH LINE ZAROOR ADD KAREIN

# --- Configuration ---
API_ID = 24250238
API_HASH = "cb3f118ce5553dc140127647edcf3720"
BOT_TOKEN = "7511520910:AAFpmjNQZFCyqDILQV7GzLpnbxPZ4CEhXxw"
ALLOWED_USER = 6175650047

# Define URLs and headers
BASE_URL = 'https://online.utkarsh.com/'
LOGIN_URL = 'https://online.utkarsh.com/web/Auth/login'
TILES_DATA_URL = 'https://online.utkarsh.com/web/Course/tiles_data'
LAYER_TWO_DATA_URL = 'https://online.utkarsh.com/web/Course/get_layer_two_data'
META_SOURCE_URL = 'https://application.utkarshapp.com/index.php/data_model/meta_distributer/on_request_meta_source'
API_URL = "https://application.utkarshapp.com/index.php/data_model"

# Encryption Keys & IVs
COMMON_KEY = b"%!^F&^$)&^$&*$^&"
COMMON_IV = b"#*v$JvywJvyJDyvJ"
KEY_CHARS = "%!F*&^$)_*%3f&B+"
IV_CHARS = "#*$DJvyw2w%!_-$@"

# Session and Headers
session = requests.Session()
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

# --- Utility Functions ---
def handle_error(message, exception=None):
    print(f"Error: {message}")
    if exception:
        print(f"Exception details: {exception}")

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
        print(f"Decryption error: {e}")
        return None

def decrypt_and_load_json(enc):
    decrypted_data = decrypt_stream(enc)
    if decrypted_data:
        try:
            return json.loads(decrypted_data)
        except json.JSONDecodeError as e:
            print(f"JSON decoding error: {e}")
    return None

def sanitize_filename(name):
    s = str(name).strip().replace(' ', '_')
    s = re.sub(r'(?u)[^-\w.]', '', s)
    return s

def process_content_item(item, course_id, subject_name, topic_title, key, iv):
    try:
        item_id = item.get("id")
        item_title = item.get("title")
        tile_id = item["payload"]["tile_id"]
        
        payload = {
            "course_id": course_id,
            "device_id": "server_does_not_validate_it",
            "device_name": "server_does_not_validate_it",
            "download_click": "0",
            "name": f"{item_id}_0_0",
            "tile_id": tile_id,
            "type": "video"
        }
        
        response_data = post_request("/meta_distributer/on_request_meta_source", payload, key=key, iv=iv)
        content_data = response_data.get("data", {})
        
        url = ""
        content_type = ""
        
        if content_data.get("is_pdf") == "1":
            content_type = "PDF"
            url = content_data.get("link", "").split("?Expires=")[0]
        else:
            content_type = "Video"
            bitrate_urls = content_data.get("bitrate_urls")
            if isinstance(bitrate_urls, list) and bitrate_urls:
                selected_url = next((q.get("url") for q in reversed(bitrate_urls) if q.get("url")), None)
                if selected_url:
                    url = selected_url.split("?Expires=")[0]
            elif content_data.get("link"):
                link = content_data.get("link")
                if ".m3u8" in link or ".pdf" in link:
                    url = link.split("?Expires=")[0]
                elif ".ws" in link and "https" in link:
                    url = link
                else:
                    url = f"https://www.youtube.com/embed/{link}"
        
        if url:
            return content_type, f"{subject_name} -> {topic_title} -> {item_title} : {url}"
    except Exception as e:
        print(f"⚠️ Content extraction error: {item_title} - {e}")
    return None, None

async def utk(course_id, message_instance: Message):
    try:
        await message_instance.edit_text("⚙️ **Step 1 of 5:** Retrieving CSRF token... 🌐")
        r1 = session.get(BASE_URL)
        csrf_token = r1.cookies.get('csrf_name')
        if not csrf_token:
            raise ValueError("CSRF token not found.")

        await message_instance.edit_text("⚙️ **Step 2 of 5:** Logging in... 🔑")
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
        u2 = session.post(LOGIN_URL, data=d1, headers=h).json()
        r2 = u2.get("response")
        dr1 = decrypt_and_load_json(r2)
        token = dr1.get("token")
        jwt = dr1.get("data", {}).get("jwt")
        h["token"] = token
        h["jwt"] = jwt
        HEADERS["jwt"] = jwt

        await message_instance.edit_text("⚙️ **Step 3 of 5:** Retrieving user profile... 🧑‍💻")
        profile = post_request("/users/get_my_profile", use_common_key=True)
        user_id = str(profile["data"]["id"])
        HEADERS["userid"] = user_id
        key = "".join(KEY_CHARS[int(i)] for i in (user_id + "1524567456436545")[:16]).encode()
        iv = "".join(IV_CHARS[int(i)] for i in (user_id + "1524567456436545")[:16]).encode()
    
        await message_instance.edit_text("⚙️ **Step 4 of 5:** Fetching course structure... 🗺️")
        d3 = {"course_id": course_id, "revert_api": "1#0#0#1", "parent_id": 0, "tile_id": "15330", "layer": 1, "type": "course_combo"}
        encrypted = encrypt_stream(json.dumps(d3))
        d4 = {'tile_input': encrypted, 'csrf_name': csrf_token}
        u4 = session.post(TILES_DATA_URL, headers=h, data=d4).json()
        r4 = u4.get("response")
        dr3 = decrypt_and_load_json(r4)

        if not dr3 or "data" not in dr3 or not dr3["data"]:
            raise ValueError("No course data found.")

        buffer = StringIO()
        
        await message_instance.edit_text("⚙️ **Step 5 of 5:** Extracting content links... ⏳")
        
        video_count = 0
        pdf_count = 0
        
        course_title = dr3["data"][0].get("title", f"Batch_{course_id}")
        output_filename = f"{sanitize_filename(course_title)}.txt"

        for course in dr3["data"]:
            course_title = course.get("title")
            
            d5 = {"course_id": course.get("id"), "layer": 1, "page": 1, "parent_id": course.get("id"), "revert_api": "1#1#0#1", "tile_id": "0", "type": "content"}
            d6 = {'tile_input': encrypt_stream(json.dumps(d5)), 'csrf_name': csrf_token}
            dr4 = decrypt_and_load_json(session.post(TILES_DATA_URL, headers=h, data=d6).json()["response"])
            
            if dr4 and "data" in dr4 and "list" in dr4["data"]:
                subjects = dr4["data"]["list"]
                
                for subj in subjects:
                    sfi = subj.get("id")
                    sfn = subj.get("title", "").strip().replace("\n", " ")
                    
                    d7 = {"course_id": course.get("id"), "parent_id": course.get("id"), "layer": 2, "page": 1, "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, "topic_id": sfi, "type": "content"}
                    d8 = {'layer_two_input_data': base64.b64encode(json.dumps(d7).encode()).decode(), 'csrf_name': csrf_token}
                    dr5 = decrypt_and_load_json(session.post(LAYER_TWO_DATA_URL, headers=h, data=d8).json()["response"])
                    
                    if dr5 and "data" in dr5 and "list" in dr5["data"]:
                        topics = dr5["data"]["list"]
                        
                        for topic in topics:
                            ti = topic.get("id")
                            tt = topic.get("title")
                            
                            d9 = {"course_id": course.get("id"), "parent_id": course.get("id"), "layer": 3, "page": 1, "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, "topic_id": ti, "type": "content"}
                            d10 = {'layer_two_input_data': base64.b64encode(json.dumps(d9).encode()).decode(), 'csrf_name': csrf_token}
                            dr6 = decrypt_and_load_json(session.post(LAYER_TWO_DATA_URL, headers=h, data=d10).json()["response"])
                            
                            if dr6 and "data" in dr6 and "list" in dr6["data"]:
                                items_to_process = dr6["data"]["list"]
                                if items_to_process:
                                    await message_instance.edit_text(f"Extracting: **{sfn}** -> **{tt}** ({len(items_to_process)} items)...")
                                    with ThreadPoolExecutor(max_workers=200) as executor:
                                        futures = [executor.submit(process_content_item, item, course.get("id"), sfn, tt, key, iv) for item in items_to_process]
                                        for future in as_completed(futures):
                                            content_type, result = future.result()
                                            if result:
                                                buffer.write(result + "\n")
                                                if content_type == "Video":
                                                    video_count += 1
                                                elif content_type == "PDF":
                                                    pdf_count += 1
        
        total_links = video_count + pdf_count
        
        summary = f"📈 **Extraction Summary for '{course_title}' (Batch ID: {course_id})**\n\n"
        summary += f"▶️ Total Videos Found: {video_count}\n"
        summary += f"📄 Total PDFs Found: {pdf_count}\n"
        summary += f"🔗 Total Links Extracted: {total_links}\n"
        summary += "\n" + "="*50 + "\n\n"
        summary += "📦 **Extracted Links**\n" + "-"*20 + "\n"
        summary += buffer.getvalue()
        
        with open(output_filename, "w", encoding='utf-8') as f:
            f.write(summary)
        
        await message_instance.edit_text("✅ Extraction complete! Sending file...")
        return output_filename

    except asyncio.TimeoutError:
        await message_instance.reply("⏳ Timed out! Please restart the process with /utkarsh.")
    except Exception as e:
        await message_instance.reply(f"❌ An error occurred during extraction: {e}")
        handle_error("Main extraction process failed", e)
        return None
    
# --- Telegram Bot ---
bot = Client("utkarqwesh_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

@bot.on_message(filters.command("start"))
async def start_handler(client: Client, message: Message):
    keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🚀 Start Extraction", callback_data="utkarsh")
            ]
        ]
    )
    await message.reply(
        "👋 Welcome to the **Utkarsh Course Extractor Bot**!\n\n"
        "I can extract all video and PDF links from a specific Utkarsh course.\n\n"
        "Press the button below to get started.",
        reply_markup=keyboard
    )

@bot.on_callback_query(filters.regex("utkarsh"))
async def start_extraction_callback(client, callback_query):
    await callback_query.answer()  # Acknowledge the button press
    message = callback_query.message
    
    if callback_query.from_user.id != ALLOWED_USER:
        await message.reply("❌ You are not authorized to use this bot.")
        return

    try:
        ask = await message.reply("📥 Please send the **Batch ID** for the course you want to extract:")
        response = await bot.listen(message.chat.id, timeout=300)
        course_id = response.text.strip()
        
        await message.reply(f"🔄 Starting extraction for Batch ID `{course_id}`. This may take some time... ⏳")
        
        status_message = await message.reply("⚙️ Initializing extraction process...")
        
        output_filename = await utk(course_id, status_message)
        
        if output_filename and os.path.exists(output_filename) and os.path.getsize(output_filename) > 0:
            await message.reply_document(output_filename, caption=f"✅ Extraction completed successfully for Batch ID `{course_id}`!")
            os.remove(output_filename)
        else:
            await message.reply("⚠️ Extraction completed, but no content was found or saved.")

    except asyncio.TimeoutError:
        await message.reply("⏳ Timed out! Please restart the process with /utkarsh.")
    except Exception as e:
        await message.reply(f"❌ An error occurred: {e}")

# Correct way to run the bot in Google Colab's event loop
print("🚀 Bot started! Listening for commands...")
async def main():
    await bot.start()
    await bot.idle()

if __name__ == "__main__":
    asyncio.run(main())
