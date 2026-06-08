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

# --- UI Helper Functions ---

def strength_level(password: str) -> tuple[str, str] | None:
    """Returns (label, color) or None if password is empty.

    - Empty string  → None
    - len < 8       → ("Weak",     "#EF4444")  # red
    - 8 <= len <= 15→ ("Moderate", "#F59E0B")  # yellow
    - len >= 16     → ("Strong",   "#10B981")  # green
    """
    if not password:
        return None
    n = len(password)
    if n < 8:
        return ("Weak", "#EF4444")
    elif n <= 15:
        return ("Moderate", "#F59E0B")
    else:
        return ("Strong", "#10B981")


def strength_indicator(password: str) -> None:
    """Render a colored strength bar and label for the given password.

    Calls strength_level(password). If the result is None (empty password),
    renders nothing and returns. Otherwise emits a colored bar and label
    using the CSS classes defined by inject_css().

    Covers requirements 3.4, 3.5, 3.6, 3.7.
    """
    result = strength_level(password)
    if result is None:
        return

    label, _color = result
    css_class = label.lower()  # "weak", "moderate", or "strong"

    st.markdown(
        f'<div class="strength-bar-container">'
        f'<div class="strength-bar {css_class}"></div>'
        f'</div>'
        f'\n<p class="strength-label {css_class}">{label}</p>',
        unsafe_allow_html=True,
    )


def password_field() -> str:
    """Render a password input with a visibility toggle and strength indicator.

    - Initialises st.session_state.show_password to False if not present.
    - Uses two columns: wide one for the text_input, narrow one for the toggle.
    - Renders type="default" (visible) when show_password is True, otherwise
      type="password" (masked).
    - Toggle button shows 👁 when masked, 🙈 when visible.
    - Calls strength_indicator() immediately below the columns.
    - Returns the current password string value.

    Covers requirements 3.1, 3.3, 3.4, 3.5, 3.6, 3.7.
    """
    if "show_password" not in st.session_state:
        st.session_state.show_password = False

    col_input, col_toggle = st.columns([9, 1])

    with col_input:
        input_type = "default" if st.session_state.show_password else "password"
        password = st.text_input(
            "Password",
            placeholder="Enter your password…",
            type=input_type,
            key="password_input",
        )

    with col_toggle:
        # Align the button vertically with the input by adding a small label spacer
        st.markdown("<br>", unsafe_allow_html=True)
        toggle_icon = "🙈" if st.session_state.show_password else "👁"
        if st.button(toggle_icon, key="toggle_password"):
            st.session_state.show_password = not st.session_state.show_password
            st.rerun()

    strength_indicator(password)

    return password


# --- UI Helpers ---

# SUBTITLE must be ≤ 60 characters (assert: len(SUBTITLE) <= 60)
SUBTITLE: str = "Encrypt and decrypt messages with AES-256-GCM security"
assert len(SUBTITLE) <= 60, f"SUBTITLE exceeds 60 characters: {len(SUBTITLE)}"


def render_header() -> None:
    """Render a centered app header with title and subtitle.

    Injects an HTML block via st.markdown containing the application
    title and the SUBTITLE constant, styled via the .app-header CSS
    class defined in inject_css().

    Covers requirement 1.3.
    NOTE: This function is defined here but not yet called.
    """
    st.markdown(
        f"""
<div class="app-header">
  <h1>🔐 AES-GCM Encryptor / Decryptor</h1>
  <p class="subtitle">{SUBTITLE}</p>
</div>
""",
        unsafe_allow_html=True,
    )


def inject_css() -> None:
    """Inject custom CSS overrides via st.markdown.

    Covers requirements 1.2, 1.4, 1.5, 4.3, 7.1, 7.2, 7.3.
    NOTE: This function is defined here but not yet called.
    """
    accent = "#7C3AED"
    accent_hover = "#6D28D9"

    css = f"""
<style>
/* ── Layout: centered content with max-width for wide viewports (Req 7.1) ── */
.block-container {{
    max-width: 800px;
    margin: 0 auto;
    padding-top: 2rem;
    padding-bottom: 2rem;
}}

/* ── Header centering (Req 1.3) ── */
.app-header {{
    text-align: center;
    margin-bottom: 1.5rem;
}}
.app-header h1 {{
    font-size: 2rem;
    font-weight: 700;
    margin-bottom: 0.25rem;
}}
.app-header .subtitle {{
    font-size: 1rem;
    opacity: 0.75;
    margin-top: 0;
}}

/* ── Buttons: border-radius, padding, hover accent (Req 1.5, 4.3) ── */
[data-testid="stBaseButton-primary"],
[data-testid="stBaseButton-secondary"] {{
    border-radius: 8px !important;
    padding: 10px 20px !important;
    font-weight: 600;
    transition: background-color 0.2s ease, box-shadow 0.2s ease;
}}
[data-testid="stBaseButton-primary"] {{
    background-color: {accent} !important;
    border: none !important;
    color: #ffffff !important;
}}
[data-testid="stBaseButton-primary"]:hover {{
    background-color: {accent_hover} !important;
    box-shadow: 0 4px 12px rgba(124, 58, 237, 0.4) !important;
}}
[data-testid="stBaseButton-secondary"]:hover {{
    background-color: {accent} !important;
    color: #ffffff !important;
    border-color: {accent} !important;
}}

/* ── Card containers (Req 1.5): visible background, border-radius, padding ── */
[data-testid="stVerticalBlockBorderWrapper"],
div[class*="stForm"],
.stContainer > div {{
    border-radius: 8px !important;
    padding: 8px !important;
}}
.card {{
    background-color: rgba(26, 26, 46, 0.85);
    border: 1px solid rgba(124, 58, 237, 0.25);
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 1rem;
}}

/* ── Input fields: border-radius and padding (Req 1.5) ── */
[data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea {{
    border-radius: 8px !important;
    padding: 10px 12px !important;
    transition: border-color 0.2s ease;
}}
[data-testid="stTextInput"] input:focus,
[data-testid="stTextArea"] textarea:focus {{
    border-color: {accent} !important;
    box-shadow: 0 0 0 2px rgba(124, 58, 237, 0.25) !important;
}}

/* ── Password strength bar (Req 3.4–3.7) ── */
.strength-bar-container {{
    width: 100%;
    background-color: rgba(255, 255, 255, 0.1);
    border-radius: 4px;
    height: 6px;
    margin-top: 6px;
    overflow: hidden;
}}
.strength-bar {{
    height: 100%;
    border-radius: 4px;
    transition: width 0.35s ease, background-color 0.35s ease;
}}
.strength-bar.weak {{
    width: 33%;
    background-color: #EF4444;
}}
.strength-bar.moderate {{
    width: 66%;
    background-color: #F59E0B;
}}
.strength-bar.strong {{
    width: 100%;
    background-color: #10B981;
}}
.strength-label {{
    font-size: 0.75rem;
    margin-top: 4px;
    font-weight: 500;
}}
.strength-label.weak   {{ color: #EF4444; }}
.strength-label.moderate {{ color: #F59E0B; }}
.strength-label.strong {{ color: #10B981; }}

/* ── Responsive: single-column stacked layout below 768px (Req 7.3) ── */
@media (max-width: 768px) {{
    .block-container {{
        max-width: 100% !important;
        padding-left: 1rem !important;
        padding-right: 1rem !important;
    }}
    /* Force Streamlit column containers to stack vertically */
    [data-testid="column"] {{
        width: 100% !important;
        flex: 1 1 100% !important;
        min-width: 100% !important;
    }}
    [data-testid="stHorizontalBlock"] {{
        flex-direction: column !important;
    }}
    [data-testid="stBaseButton-primary"],
    [data-testid="stBaseButton-secondary"] {{
        width: 100% !important;
    }}
    .app-header h1 {{
        font-size: 1.5rem;
    }}
}}
</style>
"""
    st.markdown(css, unsafe_allow_html=True)


# --- Action Handlers ---

def _handle_encrypt(msg: str, password: str) -> None:
    """Validate inputs and invoke encrypt(); update session state.

    Clears st.session_state.status at entry so any previous banner is
    removed before setting the new result (Req 6.5).

    Guards (Req 4.4, 4.5):
    - Empty msg      → error status "Message is required."
    - Empty password → error status "Password is required."

    On success (Req 4.6, 5.1, 6.1):
    - st.session_state.output      = blob.hex()
    - st.session_state.output_type = "cipher"
    - st.session_state.status      = {"level": "success", "message": "Encrypted successfully! ✅"}

    On any exception (should be rare for encrypt, but handled for safety):
    - st.session_state.output = None
    - st.session_state.status = {"level": "error", "message": generic sanitized message}
    """
    st.session_state.status = None
    st.session_state.output = None

    if not msg.strip():
        st.session_state.status = {"level": "error", "message": "Message is required."}
        return
    if not password:
        st.session_state.status = {"level": "error", "message": "Password is required."}
        return

    try:
        blob = encrypt(msg.encode(), password)
        st.session_state.output = blob.hex()
        st.session_state.output_type = "cipher"
        st.session_state.status = {"level": "success", "message": "Encrypted successfully! ✅"}
    except Exception:
        st.session_state.output = None
        st.session_state.status = {"level": "error", "message": "Encryption failed."}


def _handle_decrypt(ciphertext_hex: str, password: str) -> None:
    """Validate inputs and invoke decrypt(); update session state.

    Clears st.session_state.status at entry so any previous banner is
    removed before setting the new result (Req 6.5).

    Guards (Req 4.4, 4.5):
    - Empty ciphertext_hex → error status "Ciphertext is required."
    - Empty password       → error status "Password is required."

    Try/except block (Req 6.3, 6.4):
    - bytes.fromhex(ciphertext_hex.strip()) converts hex to bytes.
    - decrypt(blob, password) performs AES-GCM decryption.
    - The except block NEVER re-raises or exposes raw exception text.

    On success (Req 4.6, 5.2, 6.2):
    - st.session_state.output      = plaintext decoded as UTF-8 (with replacement)
    - st.session_state.output_type = "plain"
    - st.session_state.status      = {"level": "success", "message": "Decrypted successfully! ✅"}

    On any exception (invalid hex, wrong password, corrupted data) (Req 6.3, 6.4):
    - st.session_state.output = None
    - st.session_state.status = {"level": "error",
                                  "message": "Decryption failed: incorrect password or corrupted data."}
    """
    st.session_state.status = None
    st.session_state.output = None

    if not ciphertext_hex.strip():
        st.session_state.status = {"level": "error", "message": "Ciphertext is required."}
        return
    if not password:
        st.session_state.status = {"level": "error", "message": "Password is required."}
        return

    try:
        blob = bytes.fromhex(ciphertext_hex.strip())
        plaintext = decrypt(blob, password)
        st.session_state.output = plaintext.decode("utf-8", errors="replace")
        st.session_state.output_type = "plain"
        st.session_state.status = {"level": "success", "message": "Decrypted successfully! ✅"}
    except Exception:
        st.session_state.output = None
        st.session_state.status = {
            "level": "error",
            "message": "Decryption failed: incorrect password or corrupted data.",
        }


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
