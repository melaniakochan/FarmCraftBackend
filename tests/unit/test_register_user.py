"""
Unit tests for user registration endpoint.

These tests validate specific examples, edge cases, and integration points
using concrete test cases with known inputs and expected outputs.
"""

import json
import sys
from pathlib import Path

# Add functions directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "functions" / "register_user"))

import bcrypt
import boto3
import hashlib
import pytest
from botocore.exceptions import ClientError
from moto import mock_dynamodb

import app


@pytest.fixture
def mock_dynamodb_table():
    """Create mock DynamoDB table for testing."""
    with mock_dynamodb():
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.create_table(
            TableName='Users',
            KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )
        yield table


# ============================================================================
# Input Validation Tests (Task 11.2)
# Requirements: 1.1, 1.2, 1.3, 1.4
# ============================================================================

def test_valid_email_and_password():
    """Test extraction with specific valid email and password example."""
    event = {
        "body": json.dumps({
            "email": "user@example.com",
            "password": "securepass123"
        })
    }
    
    result = app.validate_request_body(event)
    
    assert result["email"] == "user@example.com"
    assert result["password"] == "securepass123"


def test_empty_string_email():
    """Test that empty string email raises ValueError."""
    event = {
        "body": json.dumps({
            "email": "",
            "password": "securepass123"
        })
    }
    
    # Empty email should fail email format validation
    result = app.validate_request_body(event)
    with pytest.raises(ValueError) as exc_info:
        app.validate_email(result["email"])
    
    assert "Invalid email format" in str(exc_info.value)


def test_empty_string_password():
    """Test that empty string password raises ValueError."""
    event = {
        "body": json.dumps({
            "email": "user@example.com",
            "password": ""
        })
    }
    
    result = app.validate_request_body(event)
    with pytest.raises(ValueError) as exc_info:
        app.validate_password(result["password"])
    
    assert "at least 8 characters" in str(exc_info.value)


def test_null_values_in_request_body():
    """Test that null values in request body are handled."""
    # Test null email
    event = {
        "body": json.dumps({
            "email": None,
            "password": "securepass123"
        })
    }
    
    result = app.validate_request_body(event)
    with pytest.raises((ValueError, AttributeError, TypeError)):
        app.validate_email(result["email"])


def test_extra_unexpected_fields():
    """Test that extra fields in request body are ignored."""
    event = {
        "body": json.dumps({
            "email": "user@example.com",
            "password": "securepass123",
            "extra_field": "should be ignored",
            "another_field": 12345
        })
    }
    
    result = app.validate_request_body(event)
    
    # Should successfully extract required fields
    assert result["email"] == "user@example.com"
    assert result["password"] == "securepass123"


# ============================================================================
# Password Hashing Tests (Task 11.3)
# Requirements: 3.1, 3.2, 3.3
# ============================================================================

def test_bcrypt_hash_generation_known_password():
    """Test bcrypt hash generation with known password."""
    password = "testpass123"
    
    password_hash = app.hash_password(password)
    
    # Should start with bcrypt format
    assert password_hash.startswith('$2b$12$')
    # Should be 60 characters long
    assert len(password_hash) == 60


def test_hash_different_from_plain_text():
    """Test that hash is different from plain text password."""
    password = "testpass123"
    
    password_hash = app.hash_password(password)
    
    assert password_hash != password


def test_hash_verified_with_correct_password():
    """Test that hash can be verified with correct password."""
    password = "testpass123"
    
    password_hash = app.hash_password(password)
    
    # Verification should succeed (with SHA-256 pre-hashing)
    sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    assert bcrypt.checkpw(sha256_hash.encode('utf-8'), password_hash.encode('utf-8'))


def test_hash_not_verified_with_incorrect_password():
    """Test that hash cannot be verified with incorrect password."""
    password = "testpass123"
    wrong_password = "wrongpass456"
    
    password_hash = app.hash_password(password)
    
    # Verification should fail (with SHA-256 pre-hashing)
    wrong_sha256_hash = hashlib.sha256(wrong_password.encode('utf-8')).hexdigest()
    assert not bcrypt.checkpw(wrong_sha256_hash.encode('utf-8'), password_hash.encode('utf-8'))


def test_hash_matches_bcrypt_format():
    """Test that hash matches bcrypt format pattern."""
    password = "testpass123"
    
    password_hash = app.hash_password(password)
    
    # Should match bcrypt format: $2b$12$[22 char salt][31 char hash]
    import re
    pattern = r'^\$2b\$12\$[./A-Za-z0-9]{53}$'
    assert re.match(pattern, password_hash)


# ============================================================================
# Duplicate Email Tests (Task 11.4)
# Requirements: 4.1, 4.2, 4.3
# ============================================================================

@mock_dynamodb
def test_registration_with_new_email_succeeds():
    """Test that registration with new email succeeds."""
    # Create mock DynamoDB table
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    
    event = {
        "body": json.dumps({
            "email": "newuser@example.com",
            "password": "securepass123"
        })
    }
    
    response = app.lambda_handler(event, None)
    
    assert response['statusCode'] == 201
    body = json.loads(response['body'])
    assert 'user_id' in body
    assert body['message'] == "User registered successfully"


@mock_dynamodb
def test_registration_with_existing_email_returns_409():
    """Test that registration with existing email returns 409."""
    # Create mock DynamoDB table
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Register first user
    event1 = {
        "body": json.dumps({
            "email": "duplicate@example.com",
            "password": "securepass123"
        })
    }
    response1 = app.lambda_handler(event1, None)
    assert response1['statusCode'] == 201
    
    # Try to register again with same email
    event2 = {
        "body": json.dumps({
            "email": "duplicate@example.com",
            "password": "differentpass456"
        })
    }
    response2 = app.lambda_handler(event2, None)
    
    assert response2['statusCode'] == 409
    body = json.loads(response2['body'])
    assert 'error' in body
    assert "already registered" in body['error'].lower()


@mock_dynamodb
def test_case_insensitive_email_matching():
    """Test that email matching is case-insensitive."""
    # Create mock DynamoDB table
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Register with lowercase email
    event1 = {
        "body": json.dumps({
            "email": "test@example.com",
            "password": "securepass123"
        })
    }
    response1 = app.lambda_handler(event1, None)
    assert response1['statusCode'] == 201
    
    # Try to register with uppercase email
    event2 = {
        "body": json.dumps({
            "email": "TEST@EXAMPLE.COM",
            "password": "differentpass456"
        })
    }
    response2 = app.lambda_handler(event2, None)
    
    # Should return 409 because emails match case-insensitively
    assert response2['statusCode'] == 409


# ============================================================================
# Database Integration Tests (Task 11.5)
# Requirements: 6.1, 7.1, 7.2
# ============================================================================

@mock_dynamodb
def test_successful_write_to_dynamodb():
    """Test successful write to DynamoDB with moto mock."""
    # Create mock DynamoDB table
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Create user record
    user_id = app.generate_user_id()
    email = "dbtest@example.com"
    password_hash = app.hash_password("testpass123")
    user_record = app.create_user_record(user_id, email, password_hash)
    
    # Store user
    app.store_user(user_record, 'Users')
    
    # Verify write succeeded
    response = table.get_item(Key={'id': user_id})
    assert 'Item' in response
    assert response['Item']['email'] == email


@mock_dynamodb
def test_record_retrieval_after_creation():
    """Test that record can be retrieved after creation."""
    # Create mock DynamoDB table
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Register user
    event = {
        "body": json.dumps({
            "email": "retrieve@example.com",
            "password": "securepass123"
        })
    }
    response = app.lambda_handler(event, None)
    assert response['statusCode'] == 201
    
    body = json.loads(response['body'])
    user_id = body['user_id']
    
    # Retrieve record
    db_response = table.get_item(Key={'id': user_id})
    assert 'Item' in db_response
    assert db_response['Item']['id'] == user_id
    assert db_response['Item']['email'] == "retrieve@example.com"
    assert 'password_hash' in db_response['Item']
    assert 'created_at' in db_response['Item']


@mock_dynamodb
def test_dynamodb_error_handling():
    """Test DynamoDB error handling with mocked failures."""
    # Create mock DynamoDB table
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Mock store_user to raise an exception
    original_store = app.store_user
    
    def mock_store_error(user_record, table_name):
        raise ClientError(
            {'Error': {'Code': 'ProvisionedThroughputExceededException', 'Message': 'Throttled'}},
            'PutItem'
        )
    
    app.store_user = mock_store_error
    
    try:
        event = {
            "body": json.dumps({
                "email": "error@example.com",
                "password": "securepass123"
            })
        }
        response = app.lambda_handler(event, None)
        
        # Should return 500
        assert response['statusCode'] == 500
        body = json.loads(response['body'])
        assert 'error' in body
        assert body['error'] == "Internal server error"
    finally:
        # Restore original function
        app.store_user = original_store


@mock_dynamodb
def test_dynamodb_write_failure_returns_500():
    """Test that DynamoDB write failure returns 500."""
    # Create mock DynamoDB table
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Mock boto3 to raise an error
    original_resource = boto3.resource
    
    def mock_resource_error(*args, **kwargs):
        resource = original_resource(*args, **kwargs)
        original_table = resource.Table
        
        def mock_table(name):
            table_obj = original_table(name)
            original_put = table_obj.put_item
            
            def mock_put_error(*args, **kwargs):
                raise ClientError(
                    {'Error': {'Code': 'InternalServerError', 'Message': 'Internal error'}},
                    'PutItem'
                )
            
            table_obj.put_item = mock_put_error
            return table_obj
        
        resource.Table = mock_table
        return resource
    
    boto3.resource = mock_resource_error
    
    try:
        event = {
            "body": json.dumps({
                "email": "writefail@example.com",
                "password": "securepass123"
            })
        }
        response = app.lambda_handler(event, None)
        
        # Should return 500
        assert response['statusCode'] == 500
    finally:
        # Restore original function
        boto3.resource = original_resource


# ============================================================================
# Response Format Tests (Task 11.6)
# Requirements: 8.4, 9.1, 9.2, 9.3, 9.4
# ============================================================================

@mock_dynamodb
def test_201_response_structure():
    """Test 201 response structure with specific example."""
    # Create mock DynamoDB table
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    
    event = {
        "body": json.dumps({
            "email": "success@example.com",
            "password": "securepass123"
        })
    }
    
    response = app.lambda_handler(event, None)
    
    assert response['statusCode'] == 201
    assert 'headers' in response
    assert response['headers']['Content-Type'] == 'application/json'
    
    body = json.loads(response['body'])
    assert 'user_id' in body
    assert 'message' in body
    assert body['message'] == "User registered successfully"


def test_400_response_for_missing_email():
    """Test 400 response structure for missing email."""
    event = {
        "body": json.dumps({
            "password": "securepass123"
        })
    }
    
    response = app.lambda_handler(event, None)
    
    assert response['statusCode'] == 400
    assert 'headers' in response
    assert response['headers']['Content-Type'] == 'application/json'
    
    body = json.loads(response['body'])
    assert 'error' in body
    assert "Missing required field: email" in body['error']


@mock_dynamodb
def test_409_response_for_duplicate_email():
    """Test 409 response structure for duplicate email."""
    # Create mock DynamoDB table
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Register first user
    event1 = {
        "body": json.dumps({
            "email": "conflict@example.com",
            "password": "securepass123"
        })
    }
    app.lambda_handler(event1, None)
    
    # Try to register again
    event2 = {
        "body": json.dumps({
            "email": "conflict@example.com",
            "password": "differentpass456"
        })
    }
    response = app.lambda_handler(event2, None)
    
    assert response['statusCode'] == 409
    assert 'headers' in response
    assert response['headers']['Content-Type'] == 'application/json'
    
    body = json.loads(response['body'])
    assert 'error' in body
    assert "already registered" in body['error'].lower()


@mock_dynamodb
def test_500_response_for_dynamodb_error():
    """Test 500 response structure for DynamoDB error."""
    # Create mock DynamoDB table
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Mock to raise error
    original_store = app.store_user
    
    def mock_store_error(user_record, table_name):
        raise Exception("Database error")
    
    app.store_user = mock_store_error
    
    try:
        event = {
            "body": json.dumps({
                "email": "servererror@example.com",
                "password": "securepass123"
            })
        }
        response = app.lambda_handler(event, None)
        
        assert response['statusCode'] == 500
        assert 'headers' in response
        assert response['headers']['Content-Type'] == 'application/json'
        
        body = json.loads(response['body'])
        assert 'error' in body
        assert body['error'] == "Internal server error"
    finally:
        app.store_user = original_store


def test_content_type_header_in_all_responses():
    """Test that Content-Type header is present in all responses."""
    # Test 400 response
    event_400 = {"body": json.dumps({"password": "securepass123"})}
    response_400 = app.lambda_handler(event_400, None)
    assert response_400['headers']['Content-Type'] == 'application/json'
    
    # Test invalid JSON
    event_invalid = {"body": "{invalid json}"}
    response_invalid = app.lambda_handler(event_invalid, None)
    assert response_invalid['headers']['Content-Type'] == 'application/json'


# ============================================================================
# Edge Case Tests (Task 11.7)
# Requirements: 10.1, 10.2, 11.1, 11.2
# ============================================================================

def test_very_long_email():
    """Test with very long email (255+ characters)."""
    # Create email with 255+ characters
    long_email = "a" * 240 + "@example.com"  # 252 characters
    
    event = {
        "body": json.dumps({
            "email": long_email,
            "password": "securepass123"
        })
    }
    
    result = app.validate_request_body(event)
    # Should extract successfully
    assert result["email"] == long_email
    
    # Should validate successfully (email format is valid)
    normalized_email = app.validate_email(result["email"])
    assert normalized_email == long_email.lower()


def test_very_long_password():
    """Test with very long password (1000+ characters)."""
    long_password = "a" * 1000
    
    # Should pass validation (no max length)
    app.validate_password(long_password)
    
    # Should hash successfully
    password_hash = app.hash_password(long_password)
    assert password_hash.startswith('$2b$12$')
    
    # Should verify correctly (with SHA-256 pre-hashing)
    sha256_hash = hashlib.sha256(long_password.encode('utf-8')).hexdigest()
    assert bcrypt.checkpw(sha256_hash.encode('utf-8'), password_hash.encode('utf-8'))


def test_special_characters_in_email():
    """Test with special characters in email (plus addressing)."""
    special_email = "user+tag@example.com"
    
    # Should validate successfully
    normalized = app.validate_email(special_email)
    assert normalized == special_email.lower()


def test_unicode_characters_in_password():
    """Test with unicode characters in password."""
    unicode_password = "pässwörd123🔒"
    
    # Should pass validation
    app.validate_password(unicode_password)
    
    # Should hash successfully
    password_hash = app.hash_password(unicode_password)
    assert password_hash.startswith('$2b$12$')
    
    # Should verify correctly (with SHA-256 pre-hashing)
    sha256_hash = hashlib.sha256(unicode_password.encode('utf-8')).hexdigest()
    assert bcrypt.checkpw(sha256_hash.encode('utf-8'), password_hash.encode('utf-8'))


def test_email_with_multiple_at_symbols():
    """Test with email containing multiple @ symbols."""
    invalid_email = "user@@example.com"
    
    # Should fail validation
    with pytest.raises(ValueError) as exc_info:
        app.validate_email(invalid_email)
    
    assert "Invalid email format" in str(exc_info.value)


def test_whitespace_only_password():
    """Test with whitespace-only password (should fail validation)."""
    whitespace_password = "       "  # 7 spaces
    
    # Should fail length validation
    with pytest.raises(ValueError) as exc_info:
        app.validate_password(whitespace_password)
    
    assert "at least 8 characters" in str(exc_info.value)
    
    # Even with 8+ spaces, it should technically pass validation
    # (though it's a weak password, the requirement is only length)
    long_whitespace = "        "  # 8 spaces
    app.validate_password(long_whitespace)  # Should not raise
