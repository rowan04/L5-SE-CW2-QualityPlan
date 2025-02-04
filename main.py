"""
Main functionality for the smart home app.
"""

import logging

from python.database import AccessUserDatabase
import hashlib
import re

log = logging.getLogger(__name__)
handler = logging.StreamHandler()  # Logs to the terminal
log.addHandler(handler)  # Adds handler to log
log.setLevel(logging.INFO)  # Ensure INFO and above are logged
handler.setLevel(logging.INFO)  # Ensure the handler also logs INFO and above

class SmartHomeApp:
    def __init__(self):
        self.database = AccessUserDatabase()
        self.logged_in_user_id = None

    def hash_password(self, password):
        """Hashes the password using SHA-256."""
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return hashed_password

    def verify_username(self, username):
        if 1 < len(username) < 30:
            return True
        log.info("username must be between 1 and 30 characters.")
        return False

    def verify_email(self, email):
        if re.fullmatch(r"[^@]+@[^@]+\.[^@]+", email):
            return True
        log.info("email did not contain '@' and/or '.'")
        return False

    def verify_password(self, password, email):
        weak_passwords = ["password", "123456", "qwerty", "abc123"]

        if len(password) < 8:
            log.info("Password must be at least 8 characters long.")
            return False

        if password.lower() in weak_passwords:
            log.info("Password is too weak.")
            return False

        if email == password.lower():
            log.info("Password cannot be the same as the email.")
            return False

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+" for c in password)

        if not (has_lower and has_upper and has_digit and has_special):
            log.info(
                "Password must contain a mix of lowercase, uppercase, "
                "digits, and special characters"
            )
            return False

        return True

    def sign_up(self):
        """Allows a new user to sign up."""
        username = input("Enter a username: ")
        email = input("Enter an email: ")
        password = input("Enter a password: ")

        email = email.lower()

        if not self.verify_username(username):
            return

        if not self.verify_email(email):
            return

        if not self.verify_password(password, email):
            return

        hashed_password = self.hash_password(password)

        self.database.add_user(username, email, hashed_password)
        log.info("Sign-up successful!")

    def login(self):
        """Logs in an existing user."""
        email = input("Enter your email: ")
        password = input("Enter your password: ")
        hashed_password = self.hash_password(password)

        user_id = self.database.get_id_from_email(email)
        if user_id:
            stored_password = self.database.get_password(user_id)
            if stored_password == hashed_password:
                self.logged_in_user_id = user_id
                log.info(
                    "Login successful! Welcome back, %s.", 
                    self.database.get_username(user_id)
                )
                return
        # To protect user's emails and passwords,
        # do not specify whether the password or email is incorrect.
        log.info("Incorrect email or password.")

    def update_email(self):
        """Updates the email of the logged-in user."""
        if self.logged_in_user_id is None:
            log.info("You must be logged in to update your email.")
            return

        new_email = input("Enter your new email: ")
        if not self.verify_email(new_email):
            return
        self.database.update_email(self.logged_in_user_id, new_email)
        log.info("Email updated successfully!")

    def delete_user(self):
        """Deletes the logged in user"""
        if self.logged_in_user_id is None:
            log.info("You must be logged in to delete your account.")
            return

        self.database.delete_user(self.logged_in_user_id)
        self.logged_in_user_id = None
        log.info("User deleted successfully.")

    def start(self):
        """Main menu for the smart home app."""
        while True:
            log.info("\nWelcome to the Smart Home App!")
            log.info("1. Sign Up")
            log.info("2. Log In")
            log.info("3. Update Email")
            log.info("4. Delete User")
            log.info("5. Exit")
            choice = input("Choose an option: ")

            if choice == "1":
                self.sign_up()
            elif choice == "2":
                self.login()
            elif choice == "3":
                self.update_email()
            elif choice == "4":
                self.delete_user()
            elif choice == "5":
                log.info("Goodbye!")
                break
            else:
                log.info("Invalid option. Please try again.")


if __name__ == "__main__":
    app = SmartHomeApp()
    app.start()
