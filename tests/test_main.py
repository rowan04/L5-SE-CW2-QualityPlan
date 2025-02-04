"""
Unit tests for testing the smart home app.
"""

from main import SmartHomeApp
import hashlib

class TestSuccess:
    def setup_method(self):
        """
        pytest method ran before each pytest to set it up
        """
        self.app = SmartHomeApp()

    def test_hash_password(self):
        password = "securepassword123"
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        
        actual_hash = self.app.hash_password(password)
        
        assert expected_hash == actual_hash
