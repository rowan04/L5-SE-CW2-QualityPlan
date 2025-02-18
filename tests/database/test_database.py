import pytest
from unittest.mock import patch
from python.exceptions import (
    DuplicateRecordError,
    GetUserFromIdError,
    GetIdFromEmailError,
)
from datetime import datetime


class TestGetIdFromEmail:
    """
    Test the `get_id_from_email` function for both success and failure cases.
    """

    def test_get_id_from_email_success(self, access_db, create_user):
        """Test that the correct user ID is retrieved when the email exists."""

        # Try to get the user ID based on the email
        user_id = access_db.get_id_from_email(email="testuser@example.com")

        # Assert that the correct user ID is returned
        assert user_id == 1

    def test_get_id_from_email_not_found(self, access_db):
        """Test that a GetIdFromEmailError is raised when the email does not exist."""

        # Test that the exception is raised
        with pytest.raises(GetIdFromEmailError) as exc_info:
            access_db.get_id_from_email(email="testuser@example.com")

        # Check the exception message
        assert str(exc_info.value) == "User with email testuser@example.com not found"


class TestAccessUserDatabase:
    """Test add_user success cases and potential failures"""

    def test_add_user_success(self, access_db):
        """Test successful user addition."""
        with patch("python.database.log.info") as mock_log:
            access_db.add_user("newuser", "newuser@example.com", "hashed_password")
            mock_log.assert_called_with("User %s added successfully!", "newuser")

    def test_add_user_duplicate_email(self, access_db, create_user):
        """Test that DuplicateRecordError is raised when the email is already in use."""
        with pytest.raises(DuplicateRecordError):
            access_db.add_user("testuser", "testuser@example.com", "hashed_password")


class TestRemoveUser:
    """
    Test removing a user from the database.
    Includes tests for both success and failure cases.
    """

    def test_remove_user_success(self, access_db, create_user):
        """Test that a user is successfully removed from the database."""

        # Check if the user exists before removal
        user_exists = access_db.get_id_from_email("testuser@example.com")
        assert user_exists == 1

        # Remove the user with ID 1
        access_db.remove_user(user_id=1)

        # Try to retrieve the user's ID after removal, expecting an exception
        with pytest.raises(GetIdFromEmailError):
            access_db.get_id_from_email("testuser@example.com")

    def test_remove_user_not_found(self, access_db):
        """Test that trying to remove a non-existing user raises GetUserFromIdError."""

        # Try to remove a user with ID 1 (non-existent user)
        with pytest.raises(GetUserFromIdError):
            access_db.remove_user(user_id=1)


class TestGetUserInfo:
    """
    Test User information retrieving.
    Includes separate tests for each field type and errors.
    """

    def test_get_password_success(self, access_db, create_user):
        """Test that the correct password hash is retrieved for an existing user."""
        password_hash = access_db.get_user_info(user_id=1, field="password_hash")
        # password would be hashed in the actual database
        # it is not in tests for ease of use
        assert password_hash == "hashed_password"

    def test_get_username_success(self, access_db, create_user):
        """Test that the correct username is retrieved for an existing user."""
        username = access_db.get_user_info(user_id=1, field="username")
        assert username == "testuser"

    def test_get_email_success(self, access_db, create_user):
        """Test that the correct email is retrieved for an existing user."""
        email = access_db.get_user_info(user_id=1, field="email")
        assert email == "testuser@example.com"

    def test_get_date_created_success(self, access_db, create_user):
        """Test that the correct creation date is retrieved for an existing user."""
        created_at = access_db.get_user_info(user_id=1, field="created_at")
        # Checks a datetime is returned
        assert isinstance(created_at, datetime)

    def test_get_user_not_found(self, access_db):
        """Test that a GetUserFromIdError is raised when the user does not exist."""
        with pytest.raises(GetUserFromIdError, match="User with ID 1 not found"):
            access_db.get_user_info(user_id=1, field="password_hash")

    def test_get_user_invalid_field(self, access_db, create_user):
        """Test that a ValueError is raised for an invalid field."""
        with pytest.raises(ValueError, match="Invalid field: invalid_field"):
            access_db.get_user_info(user_id=1, field="invalid_field")

    def test_get_user_no_field(self, access_db, create_user):
        """Test that the correct user object is returned when field=None."""
        user = access_db.get_user_info(user_id=1, field=None)
        # Ensure the returned user object has the expected properties
        assert user.id == 1
        assert user.username == "testuser"
        assert user.email == "testuser@example.com"


class TestUpdateEmail:
    """Test updating user's email."""

    def test_update_email_success(self, access_db, create_user):
        """Test that the email is updated successfully."""

        new_email = "new_email@example.com"

        # Update the email for the user
        access_db.update_email(user_id=1, new_email=new_email)

        # Verify that the email was updated
        updated_email = access_db.get_user_info(user_id=1, field="email")
        print(updated_email)
        assert updated_email == new_email

    def test_update_email_user_not_found(self, access_db):
        """Test that a GetUserFromIdError is raised when the user does not exist."""

        new_email = "new_email@example.com"

        # Try to update the email of a non-existing user
        with pytest.raises(GetUserFromIdError):
            access_db.update_email(user_id=1, new_email=new_email)


"""
User class?

__init__?

get_id_from_email (done)

add_user (done)
remove_user (done)

get_user_info (done)

update_email (done)

"""
