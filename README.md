# IHARDEEPSINHYTDL
# YouTube Downloader Bot

This bot allows users to download YouTube videos and audio directly to Telegram.

## Setup Instructions

 **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   Set Up Secrets :
   Store the following secrets in your secrets manager:
   PEPPER: Encryption key.
   ENCRYPTED_API_ID: Encrypted Telegram API ID.
   ENCRYPTED_API_HASH: Encrypted Telegram API Hash.
   ENCRYPTED_ADMINS: Encrypted comma-separated admin IDs.
   BOT_T: Bot token (optional if using a user account).
   GOFILEAPI: Gofile API key (optional).


   ---

   ###  **First Run of the Bot**

   1. **Generate Encrypted Secrets**:
      Use the following script to encrypt your sensitive data before storing it in the secrets manager:

      ```python
      from cryptography.fernet import Fernet

      # Generate a pepper (only once)
      pepper = Fernet.generate_key().decode()
      print(f"Generated Pepper: {pepper}")

      # Initialize encryption
      cipher = Fernet(pepper)

      # Encrypt sensitive data
      api_id = "YOUR_TELEGRAM_API_ID"
      api_hash = "YOUR_TELEGRAM_API_HASH"
      admins = "123456789,987654321"

      encrypted_api_id = cipher.encrypt(api_id.encode()).decode()
      encrypted_api_hash = cipher.encrypt(api_hash.encode()).decode()
      encrypted_admins = cipher.encrypt(admins.encode()).decode()

      print(f"Encrypted API ID: {encrypted_api_id}")
      print(f"Encrypted API Hash: {encrypted_api_hash}")
      print(f"Encrypted Admins: {encrypted_admins}")
