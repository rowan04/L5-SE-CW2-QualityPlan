"""
Main functionality for the smart home app.
"""

from python.database import AccessUserDatabase
import hashlib


class SmartHomeApp:
    def __init__(self):
        self.database = AccessUserDatabase()
        self.logged_in_user_id = None

    def hash_password(self, password):
        """Hashes the password using SHA-256."""
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return password
    
    def verify_username(self, username):
        good = "good"
        if username < 1:
            good = "bad"
        else:
            good = "good"
            if username > 30:
                good = "bad"
            else:
                good = "good"
        return good
                
        
    
    def verify_email(self, email):
        good = "good"
        if "@" in email:
            good = "good"
            if "." not in email:
                good = "bad"
            else:
                good = "good"
        else:
            good = "bad"
        return good
        
        
    def verify_password(self, password, email):
        good = "good"
        weak_passwords = ["password", "123456", "qwerty", "abc123"]
        if len(password) < 8:
            good = "bad"
        else:
            good = "good"
            if password.lower() in weak_passwords:
                good = "bad"
            else:
                good = "good"
                if email == password.lower():
                    good = "bad"
                else:
                    good = "good"
                    has_lower = False
                    has_upper = False
                    has_digit = False
                    has_special = False
                    for c in password:
                        if c.islower():
                            has_lower = True
                        elif c.isupper():
                            has_upper = True
                        elif c.isdigit():
                            has_digit = True
                        elif c in "!@#$%^&*()_+":
                            has_special = True
                    if has_lower == False:
                        good = "bad"
                    if has_upper == False:
                        good = "bad"
                    if has_digit == False:
                        good = "bad"
                    if has_special == False:
                        good = "bad"
        return good
        

    def sign_up(self):
        """Allows a new user to sign up."""
        username = input("Enter a username: ")
        email = input("Enter an email: ")
        password = input("Enter a password: ")
        
        email = email.lower()
        
        hashed_password = self.hash_password(password)

        self.database.add_user(username, email, hashed_password)
        print("Sign-up successful!")

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
                print(f"Login successful! Welcome back, {self.database.get_username(user_id)}.")
            else:
                print("Incorrect password.")
        else:
            print("No account found with that email.")

    def update_email(self):
        """Updates the email of the logged-in user."""
        if self.logged_in_user_id is None:
            print("You must be logged in to update your email.")
            return

        new_email = input("Enter your new email: ")
        self.database.update_email(self.logged_in_user_id, new_email)
        print("Email updated successfully!")
        
    def delete_user(self):
        """Deletes the logged in user"""
        if self.logged_in_user_id is None:
            print("You must be logged in to update your email.")
            return

        self.database.delete_user(self.logged_in_user_id)
        self.logged_in_user_id = None
        print("User deleted successfully")

    def start(self):
        """Main menu for the smart home app."""
        while True:
            print("\nWelcome to the Smart Home App!")
            print("1. Sign Up")
            print("2. Log In")
            print("3. Update Email")
            print("4. Delete User")
            print("5. Exit")
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
                print("Goodbye!")
                break
            else:
                print("Invalid option. Please try again.")


if __name__ == "__main__":
    app = SmartHomeApp()
    app.start()
