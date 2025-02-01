"""
Unit tests for testing the smart home app.
"""

from main import start_smart_home

def test_start_smart_home():
    assert start_smart_home() == "The smart home app is running (whoop whoop)."
