import streamlit as st
import json
import os
import time
import base64
from hashlib import pbkdf2_hmac
from cryptography.fernet import Fernet

# --- CONFIG ---
DATA_FILE = "data.json"
KEY_FILE = "secret.key"
LOCKOUT_DURATION = 60  # seconds
MAX_ATTEMPTS = 3
SALT = "streamlit_salt"

# --- KEY SETUP ---
def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, "rb") as f:
        return f.read()

KEY = load_or_create_key()
cipher = Fernet(KEY)

# --- SESSION STATE INIT ---
for var in ["failed_attempts", "last_attempt_time", "logged_in_user"]:
    if var not in st.session_state:
        st.session_state[var] = 0 if var != "logged_in_user" else None

# --- HASHING ---
def hash_passkey(passkey, salt=SALT):
    key = pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return base64.b64encode(key).decode()

# --- DATA HANDLING ---
def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {"users": {}}
    return {"users": {}}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# --- AUTH ---
def register_user(username, password):
    data = load_data()
    if username in data["users"]:
        return False
    data["users"][username] = {
        "password": hash_passkey(password),
        "data": {}
    }
    save_data(data)
    return True

def authenticate_user(username, password):
    data = load_data()
    user = data["users"].get(username)
    if user and user["password"] == hash_passkey(password):
        return True
    return False

# --- ENCRYPTION ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- LOCKOUT CHECK ---
def check_lockout():
    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        if st.session_state.last_attempt_time is None:
            st.session_state.last_attempt_time = time.time()
        elapsed = time.time() - st.session_state.last_attempt_time
        if elapsed < LOCKOUT_DURATION:
            st.warning(f"⏳ Locked out. Try again in {int(LOCKOUT_DURATION - elapsed)} seconds.")
            st.stop()
        else:
            st.session_state.failed_attempts = 0

# --- SIDEBAR AUTH ---
if not st.session_state.logged_in_user:
    st.sidebar.title("🔐 User Authentication")
    auth_mode = st.sidebar.radio("Choose mode:", ["Login", "Register"])
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")

    if auth_mode == "Register":
        if st.sidebar.button("Register"):
            if username and password:
                if register_user(username, password):
                    st.success("✅ Registered! Please log in.")
                else:
                    st.error("❌ Username already exists.")
            else:
                st.error("⚠️ Fill in both fields.")
    else:
        if st.sidebar.button("Login"):
            if username and password:
                if authenticate_user(username, password):
                    st.session_state.logged_in_user = username
                    st.session_state.failed_attempts = 0
                    st.success(f"🔓 Welcome, {username}!")
                else:
                    st.session_state.failed_attempts += 1
                    st.session_state.last_attempt_time = time.time()
                    check_lockout()
                    st.error("❌ Invalid credentials.")
            else:
                st.error("⚠️ Fill in both fields.")

# --- MAIN APP ---
if st.session_state.logged_in_user:
    st.title("🔐 Secure Data Encryption System")
    menu = ["Store Data", "Retrieve Data", "Logout"]
    choice = st.selectbox("Menu", menu)

    data = load_data()
    user_data = data["users"][st.session_state.logged_in_user]["data"]

    if choice == "Store Data":
        st.subheader("📂 Store Data Securely")
        raw_text = st.text_area("📝 Enter data to encrypt:", key="encrypt_area")
        if st.button("🔒 Encrypt & Save"):
            if raw_text:
                encrypted = encrypt_data(raw_text)
                user_data[encrypted] = {"encrypted_text": encrypted}
                save_data(data)
                st.success("✅ Data encrypted and stored successfully!")
                with st.expander("🔐 View Encrypted Text"):
                    st.code(encrypted, language='text')
            else:
                st.error("⚠️ Please enter some data.")

    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Encrypted Data")
        encrypted_input = st.text_area("Paste encrypted text to decrypt:", key="decrypt_area")
        if st.button("🔓 Decrypt"):
            if encrypted_input in user_data:
                try:
                    decrypted = decrypt_data(encrypted_input)
                    with st.expander("📖 Decrypted Data"):
                        st.success(decrypted)
                except:
                    st.error("❌ Failed to decrypt. Is the key valid?")
            else:
                st.error("❌ Data not found.")

    elif choice == "Logout":
        st.session_state.logged_in_user = None
        st.success("🚪 Logged out successfully.")
        st.rerun()
else:
    st.title("🔐 Secure Data Encryption System")
    st.info("Please log in or register from the sidebar.")
