"""
Unit tests for the Smart Home Automation App.
"""

from main import SmartHomeApp
import hashlib


class TestSmartHomeApp:
    def setup_method(self):
        """Pytest method run before each test."""
        self.app = SmartHomeApp()

    # ----- Test Utility Functions -----

    def test_hash_password(self):
        """Tests the hashed password is returned properly"""
        password = "SecurePassword123!"
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        assert self.app.hash_password(password) == expected_hash

    def test_verify_username(self):
        """Tests that verify_username successfully validates inputted usernames"""
        assert self.app.verify_username("validUser") is True
        assert self.app.verify_username("") is False
        assert self.app.verify_username("a" * 31) is False

    def test_verify_email(self):
        """Tests that verify_email successfully validates inputted emails"""
        assert self.app.verify_email("test@example.com") is True
        assert self.app.verify_email("invalid-email") is False
        assert self.app.verify_email("user@com") is False

    def test_verify_password(self):
        """Tests that verify_password successfully validates inputted passwords"""
        # Strong pasword
        assert self.app.verify_password("StrongP@ss123", "user@example.com") is True

        # Password too short
        assert self.app.verify_password("short", "user@example.com") is False

        # Password same as email
        assert self.app.verify_password("user@example.com", "user@example.com") is False

        # Password has no special characters
        assert self.app.verify_password("NoSpecial123", "user@example.com") is False

        # Test what happens with just lower case, upper case or digits
        assert self.app.verify_password("PASSWORDUPPER", "user@example.com") is False
        assert self.app.verify_password("passwordlower", "user@example.com") is False
        assert self.app.verify_password("09295870693", "user@example.com") is False
