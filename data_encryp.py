# Streamlit based Data Encryption System

# Important Imports
import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Page Configuration
st.set_page_config(
    page_title="Secure Data Encryption System",
    page_icon="⚡",
    layout="wide"
)

# User Data Information
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# Login Detail
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempt" not in st.session_state:
    st.session_state.failed_attempt = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# If Data Is Loaded
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, passkey):
    try:
        key = generate_key(passkey)
        cipher = Fernet(key)
        return cipher.encrypt(text.encode()).decode()
    except Exception as e:
        st.error(f"Encryption error: {str(e)}")
        return None

def decrypt_text(encrypted_text, passkey):
    try:
        key = generate_key(passkey)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None

stored_data = load_data()

# Navbar
st.title("Secure Data Encryption System")
menu = ["Home", "Login", "Register", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Select Option", menu)

if choice == "Home":
    st.subheader("Welcome to the Secure Data Encryption System")
    st.markdown("This is a simple data encryption system that allows you to encrypt and decrypt data using a password.")

elif choice == "Register":
    st.subheader("Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("Username already exists")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("Registration successful")
        else:
            st.error("Please enter a username and password")

elif choice == "Login":
    st.subheader("Login")
    if time.time() < st.session_state.lockout_time:
        remaining_time = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts. Try again in {remaining_time} seconds.")
        st.stop()
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempt = 0
            st.success(f"Welcome, {username}! You have successfully logged in.")
        else:
            st.session_state.failed_attempt += 1
            remaining_attempts = 3 - st.session_state.failed_attempt
            st.error(f"Invalid username or password. {remaining_attempts} attempts remaining.")

            if st.session_state.failed_attempt >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error(f"Too many failed attempts. Try again in {LOCKOUT_DURATION} seconds.")
                st.stop()

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first to store data")
    else:
        st.subheader("Store Encrypted Data")
        data = st.text_area("Enter your data here")
        passkey = st.text_input("Enter your Encryption Key", type="password")

        if st.button("Encrypt and Store"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Data encrypted and stored successfully")
            else:
                st.error("Please enter data and passkey")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first to retrieve data")
    else:
        st.subheader("Retrieve Encrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data stored yet")
        else:
            st.write("Encrypted Data:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")
            
            encrypted_input = st.text_area("Enter the encrypted data to decrypt")
            passkey = st.text_input("Enter your Encryption Key", type="password")

            if st.button("Decrypt and Retrieve"):
                if encrypted_input and passkey:
                    result = decrypt_text(encrypted_input, passkey)
                    if result:
                        st.success("Data decrypted successfully")
                        st.text_area("Decrypted Data", result, height=200)
                    else:
                        st.error("Failed to decrypt data. Please check your passkey.")
                else:
                    st.error("Please enter both encrypted data and passkey")

              
