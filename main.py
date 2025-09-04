import requests
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
import base64
import threading
import asyncio
import time
import concurrent.futures

session = requests.Session()

# Define URLs and headers
base_url = 'https://online.utkarsh.com/'
login_url = 'https://online.utkarsh.com/web/Auth/login'
tiles_data_url = 'https://online.utkarsh.com/web/Course/tiles_data'
layer_two_data_url = 'https://online.utkarsh.com/web/Course/get_layer_two_data'
meta_source_url = '/meta_distributer/on_request_meta_source'

# Define function to handle errors
def handle_error(message, exception=None):
    print(f"Error: {message}")
    if exception:
        print(f"Exception details: {exception}")

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
        return json.loads(decrypted_data)
    except json.JSONDecodeError as e:
        print(f"JSON decoding error: {e}")
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
        print(f"Encryption error: {e}")
        return None

# Initialize session


# Process each item in the response
def extract_subjects_from_dr3(
    dr3, tiles_data_url, csrf_token, session, headers,
    encrypt_stream, decrypt_and_load_json
):
    results = []

    if "data" not in dr3 or not dr3["data"]:
        handle_error("No data found in response")
        return results

    for course in dr3.get("data", []):
        try:
            fi = course.get("id")
            tn = course.get("title")
            binfo = course.get("segment_information")
            print(f"{fi} - {tn} \n\n {binfo}")
           

            d5 = {
                "course_id": fi,
                "layer": 1,
                "page": 1,
                "parent_id": fi,
                "revert_api": "1#1#0#1",
                "tile_id": "0",
                "type": "content"
            }

            de2 = encrypt_stream(json.dumps(d5))
            d6 = {'tile_input': de2, 'csrf_name': csrf_token}
            response = session.post(tiles_data_url, headers=headers, data=d6)

            if response.ok:
                r5 = response.json().get("response")
                dr4 = decrypt_and_load_json(r5)
                for item in dr4.get("data", {}).get("list", []):
                    sfi = item.get("id")
                    sfn = item.get("title")
                    print(f"Subject ID: {sfi}, Title: {sfn}")
                    
                    results.append((fi, sfi, sfn))
            else:
                print(f"❌ Failed for {fi}: {response.status_code}")
        except Exception as e:
            handle_error(f"Error processing course ID {fi}", e)

    return results

def extract_layer_two_topics_from_flat_list(
    layer1_data, layer_two_data_url, csrf_token, session, headers, decrypt_and_load_json
):
    results = []

    for fi, sfi, sfn in layer1_data:
        try:
            d7 = {
                "course_id": fi,
                "parent_id": fi,
                "layer": 2,
                "page": 1,
                "revert_api": "1#0#0#1",
                "subject_id": sfi,
                "tile_id": 0,
                "topic_id": sfi,
                "type": "content"
            }

            b641 = json.dumps(d7)
            de3 = base64.b64encode(b641.encode()).decode()

            d8 = {
                'layer_two_input_data': de3,
                'csrf_name': csrf_token
            }

            response = session.post(layer_two_data_url, headers=headers, data=d8)
            if response.ok:
                r6 = response.json().get("response")
                dr5 = decrypt_and_load_json(r6)

                for item in dr5.get("data", {}).get("list", []):
                    ti = item.get("id")
                    tt = item.get("title")
                    print(f"Topic ID: {ti}, Title: {tt}")
                    results.append((fi, sfi, sfn, ti, tt))
            else:
                print(f"❌ Layer 2 request failed for subject {sfi} with status: {response.status_code}")
        except Exception as e:
            print(f"⚠️ Error processing subject {sfi}: {e}")

    return results



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

def extract_layer_three_links(
    layer2_data,
    layer_two_data_url,
    meta_source_url,
    csrf_token,
    session,
    headers,
    decrypt_and_load_json,
    post_request,
    key,
    iv,
    output_file="final_output.txt",
    max_workers=1000
):
    COMMON_PAYLOAD_BASE = {
        "device_id": "server_does_not_validate_it",
        "device_name": "server_does_not_validate_it",
        "download_click": "0",
        "type": "video"
    }

    youtube_template = "https://www.youtube.com/embed/"

    write_lock = threading.Lock()

    def extract_url(data):
        urls = data.get("bitrate_urls", [])
        if isinstance(urls, list):
            for q in urls:
                u = q.get("url")
                if u:
                    return u.split("?Expires=")[0]
        link = data.get("link", "")
        if link:
            if ".m3u8" in link or ".pdf" in link:
                return link.split("?Expires=")[0]
            return youtube_template + link
        return ""

    def process_item(fi, jti, ji, jt):
        try:
            payload = COMMON_PAYLOAD_BASE.copy()
            payload.update({
                "course_id": fi,
                "name": f"{ji}_0_0",
                "tile_id": jti
            })
            j5 = post_request(meta_source_url, payload, key=key, iv=iv)
            cj = j5.get("data", {})
            link = extract_url(cj)
            return f"{jt}:{link}\n" if link else None
        except Exception:
            return None

    def process_topic(data):
        fi, sfi, sfn, ti, tt = data
        try:
            layer3_payload = {
                "course_id": fi,
                "parent_id": fi,
                "layer": 3,
                "page": 1,
                "revert_api": "1#0#0#1",
                "subject_id": sfi,
                "tile_id": 0,
                "topic_id": ti,
                "type": "content"
            }

            encoded = base64.b64encode(json.dumps(layer3_payload).encode()).decode()
            d = {'layer_two_input_data': encoded, 'csrf_name': csrf_token}

            resp = session.post(layer_two_data_url, headers=headers, data=d, timeout=15)
            if not resp.ok:
                return []

            r = resp.json().get("response")
            dr6 = decrypt_and_load_json(r)
            content_list = dr6.get("data", {}).get("list", [])

            with ThreadPoolExecutor(max_workers=15) as tile_pool:
                futures = [
                    tile_pool.submit(process_item, fi, item["payload"]["tile_id"], item["id"], item["title"])
                    for item in content_list
                    if item.get("id") and item.get("payload", {}).get("tile_id")
                ]

                return [f.result() for f in as_completed(futures) if f.result()]
        except Exception:
            return []

    print(f"🚀 Launching Layer 3 parallel extraction for {len(layer2_data)} topics...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor, open(output_file, "w", buffering=16384, encoding="utf-8") as f:
        futures = [executor.submit(process_topic, topic_data) for topic_data in layer2_data]

        for future in as_completed(futures):
            try:
                results = future.result()
                if results:
                    with write_lock:
                        f.writelines(results)
            except Exception:
                continue

    print(f"✅ All video/PDF links saved to {output_file}")


import json, base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import StringIO
# course_id = input("\033[1mHey I Am x  .PLZ INPUT ANY BATCH ID TO EXTRACT THAT COURSE\033[0m : ")
# Step 1: Retrieve CSRF token
async def utk(course_id):
    try:
        r1 = session.get(base_url)
        csrf_token = r1.cookies.get('csrf_name')
        if not csrf_token:
            raise ValueError("CSRF token not found.")
    except Exception as e:
        handle_error("Failed to retrieve CSRF token", e)
        return

    # Step 2: Login
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

    try:
        u2 = session.post(login_url, data=d1, headers=h).json()
        r2 = u2.get("response")
        dr1 = decrypt_and_load_json(r2)
        token = dr1.get("token")
        jwt = dr1.get("data", {}).get("jwt")

        h["token"] = token
        h["jwt"] = jwt
        HEADERS["jwt"] = jwt
    except Exception as e:
        handle_error("Failed to log in or retrieve tokens", e)
        return

    # Step 3: Retrieve User Profile
    try:
        profile = post_request("/users/get_my_profile", use_common_key=True)
        user_id = profile["data"]["id"]
        HEADERS["userid"] = user_id

        key = "".join(key_chars[int(i)] for i in (user_id + "1524567456436545")[:16]).encode()
        iv = "".join(iv_chars[int(i)] for i in (user_id + "1524567456436545")[:16]).encode()
    except Exception as e:
        handle_error("Failed to retrieve user profile", e)
        return

    # Step 4: Input course ID
    
    d3 = {
        "course_id": course_id,
        "revert_api": "1#0#0#1",
        "parent_id": 0,
        "tile_id": "15330",
        "layer": 1,
        "type": "course_combo"
    }

    # Step 5: Encrypt and send course tile request
    try:
        encrypted = encrypt_stream(json.dumps(d3))
        d4 = {'tile_input': encrypted, 'csrf_name': csrf_token}
        u4 = session.post(tiles_data_url, headers=h, data=d4).json()
        r4 = u4.get("response")
        dr3 = decrypt_and_load_json(r4)
    except Exception as e:
        handle_error("Failed to retrieve course data", e)
        return

    # Step 6: Extract Subject Info (Layer 1)
    start = time.time()
    

    def sanitize_filename(name):
        return name.replace('/', '_').replace(':', '_').replace('|', '_')

    def process_video_item(video_item, fi, subject_name, key, iv):
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
            cj = j5.get("data", [])
            if cj:
                qo = cj.get("bitrate_urls", [])
                if qo and isinstance(qo, list):
                    for index in [3, 2, 1, 0]:
                        if len(qo) > index:
                            selected_vu = qo[index].get("url", "")
                            if selected_vu:
                                pu = selected_vu.split("?Expires=")[0]
                                return f"({subject_name}) | {jt} : {pu}"
                else:
                    vu = cj.get("link", "")
                    if vu:
                        if ".m3u8" in vu or ".pdf" in vu:
                            pu = vu.split("?Expires=")[0]
                        elif ".ws" in vu and "https" in vu:
                            pu = vu
                        else:
                            pu = f"https://www.youtube.com/embed/{vu}"
                        return f"({subject_name}) | {jt} : {pu}"
        except Exception as e:
            print(f"⚠️ Video error: {video_item.get('title')} - {e}")
        return None

    # 🔁 Start main scraping
    for course in dr3.get("data", []):
        try:
            fi = course.get("id")
            tn = course.get("title")
            binfo = course.get("segment_information")
            print(f"📚 {fi} - {tn}\n{binfo}")

            buffer = StringIO()  # 🧠 Memory buffer for speed

            # Layer 1
            d5 = {"course_id": fi, "layer": 1, "page": 1, "parent_id": fi, "revert_api": "1#1#0#1", "tile_id": "0", "type": "content"}
            d6 = {'tile_input': encrypt_stream(json.dumps(d5)), 'csrf_name': csrf_token}
            dr4 = decrypt_and_load_json(session.post(tiles_data_url, headers=h, data=d6).json()["response"])

            for subj in dr4["data"]["list"]:
                sfi = subj.get("id")
                sfn = subj.get("title").strip().replace("\n", " ")
                print(f"📘 Subject: {sfn}")

                # Layer 2
                d7 = {"course_id": fi, "parent_id": fi, "layer": 2, "page": 1, "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, "topic_id": sfi, "type": "content"}
                d8 = {'layer_two_input_data': base64.b64encode(json.dumps(d7).encode()).decode(), 'csrf_name': csrf_token}
                dr5 = decrypt_and_load_json(session.post(layer_two_data_url, headers=h, data=d8).json()["response"])

                for topic in dr5["data"]["list"]:
                    ti = topic.get("id")
                    tt = topic.get("title")

                    # Layer 3
                    d9 = {"course_id": fi, "parent_id": fi, "layer": 3, "page": 1, "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, "topic_id": ti, "type": "content"}
                    d10 = {'layer_two_input_data': base64.b64encode(json.dumps(d9).encode()).decode(), 'csrf_name': csrf_token}
                    dr6 = decrypt_and_load_json(session.post(layer_two_data_url, headers=h, data=d10).json()["response"])

                    if "data" in dr6 and "list" in dr6["data"]:
                        video_items = dr6["data"]["list"]
                        with ThreadPoolExecutor(max_workers=200) as executor:
                            futures = [
                                executor.submit(process_video_item, v, fi, sfn, key, iv)
                                for v in video_items
                            ]
                            for future in as_completed(futures):
                                result = future.result()
                                if result:
                                    buffer.write(result + "\n")

            # 💾 Final write to file
            with open("final.txt", "a", encoding='utf-8') as f:
                # f.write(f"\n\n📦 Course: {tn}\n{'='*60}\n")
                f.write(buffer.getvalue())

        except Exception as e:
            print(f"❌ Error in course {fi}: {e}")

    end = time.time()
    print(f"\n⏱️ Total Extraction Completed in {end - start:.2f} seconds.")
    print("📁 Output saved to: final_output.txt")

from pyrogram import Client, filters
from pyrogram.types import Message
from pyromod import listen
# Set these with your values
API_ID = 21179966  # 🔑 Replace with your API ID
API_HASH = "d97919fb0a3c725e8bb2a25bbb37d57c"  # 🔑 Replace with your API HASH
BOT_TOKEN = "8379064968:AAE6H8ReO9byzujjWJbaYOz8SLbZL3uGt18"  # 🤖 Replace with your bot token
ALLOWED_USER = 7326397503  # your Telegram user ID

bot = Client("utkarqwesh_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

@bot.on_message(filters.command("start") )
async def start_handler(client: Client, message: Message):
    await message.reply(
        "👋 Welcome to the Utkarsh Extractor Bot!\n\n"
        "Use /utkarsh to begin extracting a course by batch ID.\n"
        "Made by x"
    )
import os
# === /utkarsh command ===
@bot.on_message(filters.command("utkarsh") )
async def get_course_id(client: Client, message: Message):
    try:
        # Step 1: Ask for Batch ID
        ask = await message.reply("👋 Hey I Am x\n\n📥 Please send the *Batch ID* to extract:")

        # Step 2: Wait for response
        response = await bot.listen(message.chat.id, timeout=120)
        course_id = response.text.strip()

        # Step 3: Acknowledge
        await message.reply("⚙️ Starting extraction... Please wait.")

        # Step 4: Run your main logic
        await utk(course_id)  # 🔁 Your own function that extracts course and saves 'final_output.txt'

        # Step 5: Send result
        await message.reply_document("final.txt", caption=f"✅ Extraction completed!")
        os.remove("final.txt")

    except Exception as e:
        await message.reply(f"❌ Error: {e}")

# === Start the Bot ===
bot.run()


