import os
import logging
import yt_dlp
import time
import random
from telethon import TelegramClient, events, Button
from telethon.errors import FloodWaitError
from cryptography.fernet import Fernet
from flask import Flask
import threading

# Start a Web Server to keep the bot alive
app = Flask(__name__)

@app.route('/')
def home():
    return "Bot is Running!"

def run_server():
    app.run(host="0.0.0.0", port=8080, debug=False)

# Run the web server in a separate thread
threading.Thread(target=run_server, daemon=True).start()

# Load Environment Variables
PEPPER = os.getenv("PEPPER")  
ENCRYPTED_API_ID = os.getenv("ENCRYPTED_API_ID")  
ENCRYPTED_API_HASH = os.getenv("ENCRYPTED_API_HASH")  
ENCRYPTED_ADMINS = os.getenv("ENCRYPTED_ADMINS")  
BOT_TOKEN = os.getenv("BOT_T")  
GOFILE_API_KEY = os.getenv("GOFILEAPI")  

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("bot.log")]
)
logger = logging.getLogger(__name__)

# Initialize Encryption
if not PEPPER:
    raise ValueError("❌ PEPPER environment variable is missing!")
cipher = Fernet(PEPPER)

def encrypt_data(data: str) -> str:
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    try:
        return cipher.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        logger.error(f"❌ Decryption failed: {e}")
        raise ValueError("❌ Failed to decrypt sensitive data!")

# Decrypt Sensitive Data
try:
    API_ID = int(decrypt_data(ENCRYPTED_API_ID))
    API_HASH = decrypt_data(ENCRYPTED_API_HASH)
    ADMINS = set()
    for admin in decrypt_data(ENCRYPTED_ADMINS).split(","):
        admin = admin.strip()
        if admin.isdigit():
            ADMINS.add(int(admin))
except Exception as e:
    logger.error(f"❌ Error decrypting sensitive data: {e}")
    raise ValueError("❌ Failed to initialize bot due to decryption errors!")

# Admin & User Management
AUTHORIZED_USERS = set()
PENDING_REQUESTS = set()
user_data = {}

# Secure Session File
SESSION_FILE = "bot_session.session"
ENCRYPTED_SESSION_FILE = "bot_session_encrypted.session"

def encrypt_session_file():
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, "rb") as f:
            session_data = f.read()
        encrypted_data = cipher.encrypt(session_data)
        with open(ENCRYPTED_SESSION_FILE, "wb") as f:
            f.write(encrypted_data)
        os.remove(SESSION_FILE)

def decrypt_session_file():
    if os.path.exists(ENCRYPTED_SESSION_FILE):
        with open(ENCRYPTED_SESSION_FILE, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        with open(SESSION_FILE, "wb") as f:
            f.write(decrypted_data)
        os.remove(ENCRYPTED_SESSION_FILE)

decrypt_session_file()

# Initialize Telegram Client
client = TelegramClient(None, API_ID, API_HASH)

@client.on(events.NewMessage(pattern="/start"))
async def start(event):
    user_id = event.sender_id
    if user_id not in AUTHORIZED_USERS and user_id not in ADMINS:
        buttons = [[Button.inline("🔑 Request Access", data=f"request_access_{user_id}")]]
        await event.respond("🔒 You don't have access! Request admin approval.", buttons=buttons)
        return

    welcome_message = "👋 Welcome to the YouTube Downloader Bot!

Here are the available commands:
/start - Start the bot
/admins - View the list of admins and authorized users (Admin Only)
/remove_user <user_id> - Remove a user from authorized users (Admin Only)
/add_admin <user_id> - Add a new admin (Admin Only)

To download a video or audio, simply send a valid YouTube link.

Made by @i_hardeepsinh"
    await event.respond(welcome_message)

@client.on(events.NewMessage(func=lambda e: e.sender_id in AUTHORIZED_USERS or e.sender_id in ADMINS))
async def format_selection(event):
    url = event.text
    if not url.startswith(("http://", "https://")):
        return  

    user_id = event.sender_id
    user_data[user_id] = {"url": url}

    buttons = [
        [Button.inline("🎬 1080p", data="format_1080p")],
        [Button.inline("🎬 720p", data="format_720p")],
        [Button.inline("🎬 480p", data="format_480p")],
        [Button.inline("🎵 Audio Only", data="format_audio")],
    ]
    await event.respond("Select the format:", buttons=buttons)

@client.on(events.CallbackQuery(pattern=r"format_(\w+)"))
async def handle_format_selection(event):
    format_type = event.data.decode().split("_")[1]
    user_id = event.sender_id

    url = user_data.get(user_id, {}).get("url")
    if not url:
        await event.respond("❌ No URL found. Please send a valid YouTube link first.")
        return

    # Simulating human behavior to avoid YouTube detection
    time.sleep(random.uniform(2, 5))

    ydl_opts = {
        "progress_hooks": [lambda d: progress_hook(d, user_id)],
        "ratelimit": 500000,  # Limit speed to mimic human downloading
        "nocheckcertificate": True,
        "source_address": "0.0.0.0",  # Prevent blocking
        "quiet": True
    }

    if format_type == "audio":
        ydl_opts["format"] = "bestaudio/best"
        ydl_opts["postprocessors"] = [{"key": "FFmpegExtractAudio", "preferredcodec": "mp3"}]
    else:
        resolution = "1080" if format_type == "1080p" else "720" if format_type == "720p" else "480"
        ydl_opts["format"] = f"bestvideo[height<={resolution}]+bestaudio/best"

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            filename = ydl.prepare_filename(info)
            await event.answer("✅ Downloading...")
            ydl.download([url])

        if not os.path.exists(filename):
            filename = filename.rsplit(".", 1)[0] + ".mp3" if format_type == "audio" else filename

        progress_message = await client.send_message(user_id, "📤 Uploading... 0%")

        async with client.action(user_id, 'document'):
            await client.send_file(
                user_id,
                filename,
                caption="✅ Here's your file!",
                progress_callback=lambda c, t: upload_progress(c, t, user_id, progress_message)
            )

        os.remove(filename)

    except yt_dlp.utils.DownloadError as e:
        await event.respond(f"❌ Download failed: {str(e)}")
    except FloodWaitError as e:
        await event.respond(f"⏳ Flood wait: Retry after {e.seconds} seconds.")
    except Exception as e:
        await event.respond(f"❌ Error: {str(e)}")

async def progress_hook(d, user_id):
    if d['status'] == 'downloading':
        message = f"📥 Downloading... {d['_percent_str']} | Speed: {d['_speed_str']} | ETA: {d['_eta_str']}"
        await client.send_message(user_id, message)

async def upload_progress(current, total, user_id, progress_message):
    percentage = round((current / total) * 100, 2)
    await client.edit_message(user_id, progress_message, f"📤 Uploading... {percentage}%")

@client.on(events.Raw())
async def on_shutdown(event):
    if event.type == "stop":
        encrypt_session_file()

if __name__ == "__main__":
    logger.info("Bot is running...")
    client.start(bot_token=BOT_TOKEN)
    logger.info("Connected to Telegram!")
    client.run_until_disconnected()
