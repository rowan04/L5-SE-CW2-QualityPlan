import pytest
from unittest.mock import patch
from python.database import AccessUserDatabase
from python.exceptions import DuplicateRecordError


@pytest.fixture
def access_db():
    """Fixture to provide an instance of the AccessUserDatabase."""
    return AccessUserDatabase(db_url="sqlite:///:memory:")


@pytest.fixture
def create_user(access_db):
    """Helper function to add a user to the in-memory database."""
    access_db.add_user("testuser", "testuser@example.com", "hashed_password")


def test_add_user_success(access_db):
    """Test successful user addition."""
    with patch('python.database.log.info') as mock_log:  # Patch the logger here
        # Try adding a new user
        access_db.add_user("newuser", "newuser@example.com", "hashed_password")

        # Check if the success message was logged
        mock_log.assert_called_with("User %s added successfully!", "newuser")


def test_add_user_duplicate_email(access_db):
    """Test that DuplicateRecordError is raised when the email is already in use."""
    # Add a user to trigger the email conflict
    access_db.add_user("anotheruser", "duplicate@example.com", "hashed_password")

    # Ensure the exception is raised properly
    with pytest.raises(DuplicateRecordError):
        access_db.add_user("testuser", "duplicate@example.com", "hashed_password")
