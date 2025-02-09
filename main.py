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
import signal
import asyncio
from torpy import TorClient
from torpy.http.requests import TorRequests
import ssl

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
PEPPER = os.getenv("PEPPER")  # Secret encryption key (must be securely stored)
ENCRYPTED_API_ID = os.getenv("ENCRYPTED_API_ID")  # Encrypted Telegram API ID
ENCRYPTED_API_HASH = os.getenv("ENCRYPTED_API_HASH")  # Encrypted Telegram API Hash
ENCRYPTED_ADMINS = os.getenv("ENCRYPTED_ADMINS")  # Encrypted comma-separated admin IDs
BOT_TOKEN = os.getenv("BOT_T")  # Bot token (optional if using user account)
GOFILE_API_KEY = os.getenv("GOFILEAPI")  # Gofile API key for fallback storage

# Set up logging
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
    """Encrypt sensitive data using the pepper."""
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data using the pepper."""
    try:
        return cipher.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        logger.error(f"❌ Decryption failed: {e}")
        raise ValueError("❌ Failed to decrypt sensitive data!")

# Decrypt Sensitive Data
try:
    API_ID = int(decrypt_data(ENCRYPTED_API_ID))
    API_HASH = decrypt_data(ENCRYPTED_API_HASH)
    ADMINS_ENV = decrypt_data(ENCRYPTED_ADMINS).split(",")
    ADMINS = {int(admin_id.strip()) for admin_id in ADMINS_ENV if admin_id.strip().isdigit()}
except Exception as e:
    logger.error(f"❌ Error decrypting sensitive data: {e}")
    raise ValueError("❌ Failed to initialize bot due to decryption errors!")

# Admin & User Management
AUTHORIZED_USERS = set()
PENDING_REQUESTS = set()

# Temporary User Data Storage
user_data = {}

# Tor Integration
TOR_SOCKS_PORT = 9050  # Default Tor SOCKS port
TOR_CONTROL_PORT = 9051  # Default Tor control port
TOR_PASSWORD = "your_tor_password"  # Set this in your Tor configuration

def get_tor_session():
    """Create a new Tor session."""
    tor_client = TorClient()
    return tor_client.get_guard()

def rotate_tor_circuit():
    """Rotate the Tor circuit to get a new IP."""
    with TorRequests() as tor_requests:
        tor_requests.reset_identity()

# Patch for SSL compatibility with Python 3.12+
def patch_ssl_for_torpy():
    """
    Patch the ssl module to ensure compatibility with Python 3.12+.
    This replaces the deprecated `ssl.wrap_socket` with `SSLContext.wrap_socket`.
    """
    from torpy.cell_socket import TorCellSocket  # Updated import
    original_connect = TorCellSocket.connect

    def patched_connect(self):
        if self._socket is None:
            raise ConnectionError("Tor socket is not initialized!")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self._socket = context.wrap_socket(self._socket, do_handshake_on_connect=True)
        return original_connect(self)

    TorCellSocket.connect = patched_connect

# Apply the SSL patch
patch_ssl_for_torpy()

# Initialize Telethon Client
client = TelegramClient(None, API_ID, API_HASH)  # Pass None as session file if using a bot token

# Global variable to store decrypted cookies in memory
STORED_COOKIES = None

@client.on(events.NewMessage(pattern="/start"))
async def start(event):
    user_id = event.sender_id
    if user_id not in AUTHORIZED_USERS and user_id not in ADMINS:
        buttons = [
            [Button.inline("🔑 Request Access", data=f"request_access_{user_id}")]
        ]
        await event.respond("🔒 You don't have access! Request admin approval.", buttons=buttons)
        return
    welcome_message = (
        "👋 Welcome to the YouTube Downloader Bot!\n\n"
        "Here are the available commands:\n"
        "/start - Start the bot\n"
        "/admins - View the list of admins and authorized users (Admin Only)\n"
        "/remove_user  - Remove a user from authorized users (Admin Only)\n"
        "/add_admin  - Add a new admin (Admin Only)\n"
        "/upload_cookies - Upload cookies.txt (Admin Only)\n\n"
        "To download a video or audio, simply send a valid YouTube link.\n\n"
        "Made by @i_hardeepsinh"
    )
    await event.respond(welcome_message)

@client.on(events.CallbackQuery(pattern=r"request_access_(\d+)"))
async def request_access(event):
    user_id = int(event.pattern_match.group(1))
    if user_id in AUTHORIZED_USERS:
        await event.answer("✅ You already have access.")
        return
    if user_id in PENDING_REQUESTS:
        await event.answer("⏳ Your request is already pending.")
        return
    PENDING_REQUESTS.add(user_id)
    await event.answer("✅ Request sent!")
    for admin_id in ADMINS:
        await client.send_message(
            admin_id,
            f"📩 Access Request from user ID {user_id}. Approve?",
            buttons=[
                [Button.inline("✅ Approve", data=f"approve_{user_id}")],
                [Button.inline("❌ Deny", data=f"deny_{user_id}")]
            ]
        )

@client.on(events.CallbackQuery(pattern=r"(approve|deny)_(\d+)"))
async def handle_access(event):
    action, user_id = event.data.decode().split("_")
    user_id = int(user_id)
    if event.sender_id not in ADMINS:
        await event.answer("❌ Only admins can approve or deny requests.")
        return
    if action == "approve":
        AUTHORIZED_USERS.add(user_id)
        PENDING_REQUESTS.discard(user_id)
        await event.answer("✅ Access Granted!")
        await client.send_message(user_id, "✅ Your access has been approved!")
    elif action == "deny":
        PENDING_REQUESTS.discard(user_id)
        await event.answer("❌ Access Denied.")
        await client.send_message(user_id, "❌ Your access request was denied.")

@client.on(events.NewMessage(pattern="/admins"))
async def admin_list(event):
    if event.sender_id not in ADMINS:
        await event.respond("❌ Only admins can view this list.")
        return
    admin_list = ", ".join(map(str, ADMINS))
    authorized_users_list = ", ".join(map(str, AUTHORIZED_USERS))
    await event.respond(f"👑 Admins: {admin_list}\n👥 Authorized Users: {authorized_users_list}")

@client.on(events.NewMessage(pattern="/remove_user"))
async def remove_user(event):
    if event.sender_id not in ADMINS:
        await event.respond("❌ Only admins can remove users.")
        return
    try:
        user_id_to_remove = int(event.text.split(" ")[1])
        if user_id_to_remove in AUTHORIZED_USERS:
            AUTHORIZED_USERS.remove(user_id_to_remove)
            await event.respond(f"✅ Removed user {user_id_to_remove} from authorized users.")
        else:
            await event.respond(f"❌ User {user_id_to_remove} is not authorized.")
    except (IndexError, ValueError):
        await event.respond("❌ Usage: /remove_user <user_id>")

@client.on(events.NewMessage(pattern="/add_admin"))
async def add_admin(event):
    if event.sender_id not in ADMINS:
        await event.respond("❌ Only admins can add new admins.")
        return
    try:
        new_admin_id = int(event.text.split(" ")[1])
        ADMINS.add(new_admin_id)
        await event.respond(f"✅ Added user {new_admin_id} as an admin.")
    except (IndexError, ValueError):
        await event.respond("❌ Usage: /add_admin <user_id>")

@client.on(events.NewMessage(pattern="/upload_cookies"))
async def request_cookies(event):
    if event.sender_id in ADMINS:
        await event.respond("📤 Send the `cookies.txt` file.")
    else:
        await event.respond("🚫 You are not authorized to update cookies.")

@client.on(events.NewMessage(func=lambda e: e.file and e.sender_id in ADMINS))
async def receive_cookies(event):
    global STORED_COOKIES
    if event.file.name.lower() == "cookies.txt":
        # Download the file as bytes
        raw_cookies = await event.download_media(file=bytes)
        try:
            # Store the decrypted cookies in memory
            STORED_COOKIES = raw_cookies.decode()
            await event.respond("✅ `cookies.txt` stored in memory!")
        except Exception as e:
            logger.error(f"❌ Failed to process cookies: {e}")
            await event.respond("❌ Failed to process cookies. Please try again.")
    else:
        await event.respond("❌ Invalid file. Please send `cookies.txt`.")

@client.on(events.NewMessage(func=lambda e: e.sender_id in AUTHORIZED_USERS or e.sender_id in ADMINS))
async def format_selection(event):
    """Prompt the user to select a format."""
    url = event.text
    if not url.startswith(("http://", "https://")):
        return  # Ignore non-YouTube links

    # Rotate Tor circuit for anonymity
    rotate_tor_circuit()

    # Store the URL in user_data
    user_id = event.sender_id
    user_data[user_id] = {"url": url}

    buttons = [
        [Button.inline("🎥 Highest Quality", data="format_best")],
        [Button.inline("🎬 1080p", data="format_1080p")],
        [Button.inline("🎬 720p", data="format_720p")],
        [Button.inline("🎬 480p", data="format_480p")],
        [Button.inline("🎵 Audio Only", data="format_audio")],
    ]
    await event.respond("Select the desired format:", buttons=buttons)

@client.on(events.CallbackQuery(pattern=r"format_(\w+)"))
async def handle_format_selection(event):
    """Handle the selected format and proceed with the download."""
    try:
        format_type = event.data.decode().split("_")[1]
        user_id = event.sender_id

        # Retrieve the URL from user_data
        url = user_data.get(user_id, {}).get("url")
        if not url:
            await event.respond("❌ No URL found. Please send a valid YouTube link first.")
            return

        # Simulating human behavior to avoid YouTube detection
        time.sleep(random.uniform(1, 5))  # Reduced delay to 1-5 seconds

        ydl_opts = {
            "progress_hooks": [lambda d: progress_hook(d, user_id)],
            "nocheckcertificate": True,
            "source_address": "0.0.0.0",  # Prevent blocking
            "quiet": True,
            "proxy": f"socks5h://127.0.0.1:{TOR_SOCKS_PORT}",  # Use Tor SOCKS proxy
        }

        # Use stored cookies if available
        if STORED_COOKIES:
            # Write cookies to a temporary file for yt-dlp
            with open("temp_cookies.txt", "w") as f:
                f.write(STORED_COOKIES)
            ydl_opts["cookiefile"] = "temp_cookies.txt"

        if format_type == "audio":
            ydl_opts["format"] = "bestaudio/best"
            ydl_opts["postprocessors"] = [{"key": "FFmpegExtractAudio", "preferredcodec": "mp3"}]
        elif format_type == "best":
            ydl_opts["format"] = "bestvideo+bestaudio/best"
        else:
            resolution = "1080" if format_type == "1080p" else "720" if format_type == "720p" else "480"
            ydl_opts["format"] = f"bestvideo[height<={resolution}]+bestaudio/best"

        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=False)
                filename = ydl.prepare_filename(info)
                await event.answer("✅ Downloading...")
                ydl.download([url])

                # Sanitize the file name
                if not os.path.exists(filename):
                    filename = filename.rsplit(".", 1)[0] + ".mp3" if format_type == "audio" else filename

                # Send initial upload progress message
                progress_message = await client.send_message(user_id, "📤 Uploading... 0%")

                # Upload the file to Telegram with progress bar
                async with client.action(user_id, 'document'):
                    await client.send_file(
                        user_id,
                        filename,
                        caption="✅ Here's your file!",
                        progress_callback=lambda current, total: upload_progress(current, total, user_id, progress_message)
                    )

                # Delete the file after sending
                if os.path.exists(filename):
                    os.remove(filename)

                # Clean up temporary cookies file
                if os.path.exists("temp_cookies.txt"):
                    os.remove("temp_cookies.txt")

        except yt_dlp.utils.DownloadError as e:
            await event.respond(f"❌ Download failed: {str(e)}")
        except FloodWaitError as e:
            await event.respond(f"⏳ Flood wait error: Retry after {e.seconds} seconds.")
        except Exception as e:
            await event.respond(f"❌ Error: {str(e)}")

    except Exception as e:
        logger.error(f"❌ Error handling callback query: {e}")
        await event.respond("❌ An error occurred while processing your request. Please try again.")

async def progress_hook(d, user_id):
    """Send real-time download progress to the user."""
    if d['status'] == 'downloading':
        progress = d['_percent_str']
        speed = d['_speed_str']
        eta = d['_eta_str']
        message = f"📥 Downloading... {progress} | Speed: {speed} | ETA: {eta}"
        asyncio.create_task(client.send_message(user_id, message))

async def upload_progress(current, total, user_id, progress_message):
    """Update the upload progress in real-time, but only every 10 seconds or when the upload is complete."""
    percentage = round((current / total) * 100, 2)
    last_update_time = user_data.get(user_id, {}).get("last_upload_update", 0)
    current_time = time.time()

    # Update only if 10 seconds have passed since the last update or if the upload is complete
    if current_time - last_update_time >= 10 or percentage == 100:
        try:
            await client.edit_message(user_id, progress_message, f"📤 Uploading... {percentage}%")
            user_data[user_id]["last_upload_update"] = current_time  # Update the last update time
        except FloodWaitError as e:
            logger.warning(f"Flood wait error during upload progress: Retry after {e.seconds} seconds.")
            await asyncio.sleep(e.seconds)  # Wait for the required duration
            await client.edit_message(user_id, progress_message, f"📤 Uploading... {percentage}%")
            user_data[user_id]["last_upload_update"] = time.time()  # Update the last update time

# Graceful Shutdown Handler
async def graceful_shutdown():
    logger.info("Gracefully shutting down...")
    encrypt_session_file()
    await client.disconnect()

# Handle SIGTERM (used by Render to stop the service)
def handle_sigterm(signum, frame):
    logger.info("SIGTERM received. Initiating graceful shutdown...")
    asyncio.create_task(graceful_shutdown())

# Register the SIGTERM handler
signal.signal(signal.SIGTERM, handle_sigterm)

# Start the client
if __name__ == "__main__":
    logger.info("Bot is running...")
    client.start(bot_token=BOT_TOKEN)  # Pass the bot token here
    logger.info("Connected to Telegram!")
    client.run_until_disconnected()
