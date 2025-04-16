import streamlit as st
from cryptography.fernet import Fernet
import hashlib

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

cipher_suite = Fernet(st.session_state.fernet_key)

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(plain_text: str) -> str:
    return cipher_suite.encrypt(plain_text.encode()).decode()

def decrypt_data(encrypted_text: str) -> str:
    return cipher_suite.decrypt(encrypted_text.encode()).decode()

def login_page():
    st.title("🔐 Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
            st.success("Logged in successfully!")
            st.rerun()
        else:
            st.error("Invalid credentials!")

def home_page():
    st.title("📂 Secure Data Storage System")
    choice = st.selectbox("Navigation", ["Insert Data", "Retrieve Data"])
    if choice == "Insert Data":
        insert_data_page()
    else:
        retrieve_data_page()

def insert_data_page():
    st.header("➕ Store New Data")
    data_key = st.text_input("Enter a unique identifier (e.g., user1_data)")
    plain_text = st.text_area("Enter the text you want to store")
    passkey = st.text_input("Enter a passkey", type="password")
    if st.button("Store Data"):
        if data_key and plain_text and passkey:
            encrypted = encrypt_data(plain_text)
            hashed_passkey = hash_passkey(passkey)
            st.session_state.stored_data[data_key] = {
                "encrypted_text": encrypted,
                "passkey": hashed_passkey
            }
            st.success("Data stored securely!")
        else:
            st.error("All fields are required!")

def retrieve_data_page():
    st.header("🔍 Retrieve Stored Data")
    data_key = st.text_input("Enter the data identifier (e.g., user1_data)")
    passkey = st.text_input("Enter your passkey", type="password")
    if st.button("Retrieve"):
        if data_key in st.session_state.stored_data:
            stored_entry = st.session_state.stored_data[data_key]
            if hash_passkey(passkey) == stored_entry["passkey"]:
                decrypted = decrypt_data(stored_entry["encrypted_text"])
                st.success(f"Decrypted Data: {decrypted}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                st.error(f"Incorrect passkey! Attempts: {st.session_state.failed_attempts}/3")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authenticated = False
                    st.warning("Too many failed attempts. Please log in again.")
                    st.rerun()
        else:
            st.error("Data identifier not found!")

def main():
    if not st.session_state.authenticated:
        login_page()
    else:
        home_page()

if __name__ == '__main__':
    main()

