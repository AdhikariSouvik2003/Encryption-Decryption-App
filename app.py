# app.py
import streamlit as st
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Core Functions ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def encrypt(message: bytes, password: str) -> bytes:
    salt = os.urandom(16)          # random 128-bit salt
    key  = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)         # random 96-bit nonce
    ct = aesgcm.encrypt(nonce, message, None)
    return b"v1" + salt + nonce + ct

def decrypt(blob: bytes, password: str) -> bytes:
    assert blob[:2] == b"v1"
    salt  = blob[2:18]
    nonce = blob[18:30]
    ct    = blob[30:]
    key   = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# --- Streamlit UI ---
st.title("🔐 AES-GCM Message Encryptor/Decryptor")

mode = st.radio("Choose Mode:", ["Encrypt", "Decrypt"])

if mode == "Encrypt":
    message = st.text_area("Enter message to encrypt:")
    password = st.text_input("Enter password:", type="password")

    if st.button("Encrypt"):
        if not message or not password:
            st.error("Message and password required!")
        else:
            blob = encrypt(message.encode(), password)
            st.success("✅ Encrypted successfully!")
            st.code(blob.hex(), language="text")

elif mode == "Decrypt":
    ciphertext_hex = st.text_area("Paste ciphertext (hex):")
    password = st.text_input("Enter password:", type="password")

    if st.button("Decrypt"):
        try:
            blob = bytes.fromhex(ciphertext_hex.strip())
            pt = decrypt(blob, password)
            st.success("✅ Decrypted successfully!")
            st.code(pt.decode(), language="text")
        except Exception as e:
            st.error(f"❌ Decryption failed: {e}")
