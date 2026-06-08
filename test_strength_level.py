"""Unit tests for the strength_level() pure function."""
import sys
import os

# Allow importing app.py from the project root without a full Streamlit runtime.
# We mock streamlit before importing so the module-level st.* calls don't fail.
from unittest.mock import MagicMock
sys.modules.setdefault("streamlit", MagicMock())

sys.path.insert(0, os.path.dirname(__file__))
from app import strength_level

RED    = "#EF4444"
YELLOW = "#F59E0B"
GREEN  = "#10B981"


# --- Empty / None boundary ---

def test_empty_string_returns_none():
    assert strength_level("") is None


# --- Weak boundary (len < 8) ---

def test_length_1_is_weak():
    assert strength_level("a") == ("Weak", RED)

def test_length_7_is_weak():
    assert strength_level("a" * 7) == ("Weak", RED)


# --- Moderate boundary (8 <= len <= 15) ---

def test_length_8_is_moderate():
    assert strength_level("a" * 8) == ("Moderate", YELLOW)

def test_length_15_is_moderate():
    assert strength_level("a" * 15) == ("Moderate", YELLOW)


# --- Strong boundary (len >= 16) ---

def test_length_16_is_strong():
    assert strength_level("a" * 16) == ("Strong", GREEN)

def test_length_32_is_strong():
    assert strength_level("a" * 32) == ("Strong", GREEN)


# --- Label and color values are correct ---

def test_weak_label_and_color():
    label, color = strength_level("short")
    assert label == "Weak"
    assert color == RED

def test_moderate_label_and_color():
    label, color = strength_level("mediumpass")   # len == 10
    assert label == "Moderate"
    assert color == YELLOW

def test_strong_label_and_color():
    label, color = strength_level("averylongpassword")  # len == 17
    assert label == "Strong"
    assert color == GREEN
