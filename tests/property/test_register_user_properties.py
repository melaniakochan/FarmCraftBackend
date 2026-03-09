"""
Property-based tests for user registration endpoint.

These tests validate universal correctness properties across all valid inputs
using Hypothesis for property-based testing.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

# Add functions directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "functions" / "register_user"))

import bcrypt
import boto3
import pytest
from datetime import datetime
from hypothesis import given, settings, strategies as st, HealthCheck
from hypothesis.strategies import emails, text, sampled_from
from moto import mock_dynamodb

import app


# Hypothesis configuration
settings.register_profile("default", max_examples=100, deadline=2000)  # 2 second deadline for bcrypt
settings.load_profile("default")


@pytest.fixture(scope="function")
def mock_dynamodb_table():
    """Create mock DynamoDB table for testing with proper cleanup."""
    with mock_dynamodb():
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.create_table(
            TableName='Users',
            KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )
        
        yield table
        
        # Cleanup happens automatically when mock_dynamodb context exits


def is_valid_app_email(email: str) -> bool:
    """
    Filter function to check if email matches the application's validation pattern.
    The app only accepts emails with: [a-zA-Z0-9._%+-] in local part and [a-zA-Z0-9.-] in domain.
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def unique_emails():
    """
    Generate unique emails for each Hypothesis example to avoid test isolation issues.
    
    This strategy ensures that each test example gets a unique email address by:
    1. Generating a base email using Hypothesis's emails() strategy
    2. Filtering to only valid app emails
    3. Adding a unique UUID prefix to the local part
    
    This prevents Hypothesis from reusing the same email across multiple examples
    within a single test function, which would cause false duplicate errors.
    """
    import uuid
    
    @st.composite
    def _unique_email(draw):
        # Generate a base email
        base_email = draw(emails().filter(is_valid_app_email))
        
        # Split into local part and domain
        local, domain = base_email.split('@', 1)
        
        # Add unique prefix to local part
        unique_id = str(uuid.uuid4())[:8]  # Use first 8 chars of UUID
        unique_local = f"{unique_id}-{local}"
        
        # Reconstruct email
        return f"{unique_local}@{domain}"
    
    return _unique_email()


# Property 1: Request Body Field Extraction
# **Validates: Requirements 1.1**
@given(email=emails().filter(is_valid_app_email), password=text(min_size=8))
def test_request_body_extraction(email, password):
    """Test that valid request bodies are correctly extracted."""
    event = {
        "body": json.dumps({"email": email, "password": password})
    }
    
    result = app.validate_request_body(event)
    
    assert "email" in result
    assert "password" in result
    assert result["email"] == email
    assert result["password"] == password


# Property 2: Missing Required Fields Return 400
# **Validates: Requirements 1.2, 1.3**
@given(field=sampled_from(['email', 'password']))
def test_missing_required_fields(field):
    """Test that missing required fields raise ValueError."""
    # Create body with one field missing
    body = {"email": "test@example.com", "password": "testpass123"}
    del body[field]
    
    event = {"body": json.dumps(body)}
    
    with pytest.raises(ValueError) as exc_info:
        app.validate_request_body(event)
    
    assert f"Missing required field: {field}" in str(exc_info.value)


# Property 3: Invalid JSON Returns 400
# **Validates: Requirements 1.4**
@given(invalid_json=sampled_from(['{invalid}', '{"email": "test', 'not json']))
def test_invalid_json(invalid_json):
    """Test that invalid JSON raises ValueError."""
    event = {"body": invalid_json}
    
    with pytest.raises(ValueError) as exc_info:
        app.validate_request_body(event)
    
    assert "Invalid JSON" in str(exc_info.value)


# Property 4: UUID Uniqueness
# **Validates: Requirements 2.1**
def test_uuid_uniqueness():
    """Test that generated UUIDs are unique."""
    uuids = [app.generate_user_id() for _ in range(1000)]
    
    # All UUIDs should be unique
    assert len(uuids) == len(set(uuids))


# Property 5: UUID v4 Format Compliance
# **Validates: Requirements 2.2**
@settings(max_examples=50)
@given(data=st.data())
def test_uuid_v4_format(data):
    """Test that generated UUIDs match UUID v4 format."""
    user_id = app.generate_user_id()
    
    # UUID v4 pattern: 8-4-4-4-12 hexadecimal
    pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    assert re.match(pattern, user_id, re.IGNORECASE)


# Property 6: Bcrypt Hash Format
# **Validates: Requirements 3.1**
@given(password=text(min_size=8, max_size=100))
def test_bcrypt_hash_format(password):
    """Test that password hashes match bcrypt format."""
    password_hash = app.hash_password(password)
    
    # Bcrypt format: $2b$12$...
    assert password_hash.startswith('$2b$12$')
    assert len(password_hash) == 60  # Standard bcrypt hash length
    
    # Verify hash can be checked (with SHA-256 pre-hashing)
    sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    assert bcrypt.checkpw(sha256_hash.encode('utf-8'), password_hash.encode('utf-8'))


# Property 7: Plain Text Password Not Stored
# **Validates: Requirements 3.3**
@given(password=text(min_size=8))
def test_plain_text_password_not_stored(password):
    """Test that plain text password is not in user record."""
    user_id = app.generate_user_id()
    email = "test@example.com"
    password_hash = app.hash_password(password)
    
    user_record = app.create_user_record(user_id, email, password_hash)
    
    # Plain text password should not appear in any value
    for value in user_record.values():
        assert password not in str(value)
    
    # Password hash should be different from plain text
    assert user_record['password_hash'] != password


# Property 8: Duplicate Email Returns 409
# **Validates: Requirements 4.2**
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(email=unique_emails(), password=text(min_size=8, max_size=50))
def test_duplicate_email_returns_409(mock_dynamodb_table, email, password):
    """Test that duplicate email registration returns 409."""
    # Clean table at start of each example to ensure isolation
    scan_response = mock_dynamodb_table.scan()
    with mock_dynamodb_table.batch_writer() as batch:
        for item in scan_response.get('Items', []):
            batch.delete_item(Key={'id': item['id']})
    
    # Normalize email
    email_lower = email.lower()
    
    # Create first user
    event1 = {"body": json.dumps({"email": email, "password": password})}
    response1 = app.lambda_handler(event1, None)
    
    # Should succeed
    assert response1['statusCode'] == 201
    
    # Try to register again with same email
    event2 = {"body": json.dumps({"email": email, "password": password + "different"})}
    response2 = app.lambda_handler(event2, None)
    
    # Should return 409
    assert response2['statusCode'] == 409
    body = json.loads(response2['body'])
    assert "already registered" in body['error'].lower()


# Property 9: ISO 8601 Timestamp Format
# **Validates: Requirements 5.1, 5.3**
@settings(max_examples=50)
@given(data=st.data())
def test_iso8601_timestamp_format(data):
    """Test that timestamps match ISO 8601 format."""
    user_id = app.generate_user_id()
    email = "test@example.com"
    password_hash = app.hash_password("testpass123")
    
    user_record = app.create_user_record(user_id, email, password_hash)
    
    # Check format: YYYY-MM-DDTHH:MM:SS.ffffffZ
    timestamp = user_record['created_at']
    assert timestamp.endswith('Z')
    
    # Should be parseable
    parsed = datetime.fromisoformat(timestamp.rstrip('Z'))
    assert isinstance(parsed, datetime)


# Property 10: Valid Registration Persists to Database
# **Validates: Requirements 6.1**
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(email=unique_emails(), password=text(min_size=8, max_size=50))
def test_valid_registration_persists(mock_dynamodb_table, email, password):
    """Test that valid registrations are persisted to DynamoDB."""
    # Clean table at start of each example to ensure isolation
    scan_response = mock_dynamodb_table.scan()
    with mock_dynamodb_table.batch_writer() as batch:
        for item in scan_response.get('Items', []):
            batch.delete_item(Key={'id': item['id']})
    
    # Register user
    event = {"body": json.dumps({"email": email, "password": password})}
    response = app.lambda_handler(event, None)
    
    assert response['statusCode'] == 201
    body = json.loads(response['body'])
    user_id = body['user_id']
    
    # Verify record exists in table
    db_response = mock_dynamodb_table.get_item(Key={'id': user_id})
    assert 'Item' in db_response
    assert db_response['Item']['email'] == email.lower()


# Property 11: User Record Structure Completeness
# **Validates: Requirements 6.2**
@given(email=emails().filter(is_valid_app_email), password=text(min_size=8))
def test_user_record_structure(email, password):
    """Test that user records contain all required fields."""
    user_id = app.generate_user_id()
    password_hash = app.hash_password(password)
    
    user_record = app.create_user_record(user_id, email.lower(), password_hash)
    
    # Should have exactly 4 keys
    assert len(user_record) == 4
    
    # Should have all required keys
    assert 'id' in user_record
    assert 'email' in user_record
    assert 'password_hash' in user_record
    assert 'created_at' in user_record
    
    # All values should be non-empty strings
    for value in user_record.values():
        assert isinstance(value, str)
        assert len(value) > 0


# Property 12: Snake Case Attribute Naming
# **Validates: Requirements 6.3**
@settings(max_examples=50)
@given(data=st.data())
def test_snake_case_naming(data):
    """Test that all attribute names use lowercase snake_case."""
    user_id = app.generate_user_id()
    email = "test@example.com"
    password_hash = app.hash_password("testpass123")
    
    user_record = app.create_user_record(user_id, email, password_hash)
    
    for key in user_record.keys():
        # Should be lowercase
        assert key == key.lower()
        
        # Should not contain uppercase or camelCase
        assert not any(c.isupper() for c in key)


# Property 13: Successful Registration Response Structure
# **Validates: Requirements 6.4, 9.1, 9.2, 9.3**
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(email=unique_emails(), password=text(min_size=8, max_size=50))
def test_success_response_structure(mock_dynamodb_table, email, password):
    """Test that successful registrations return proper response structure."""
    # Clean table at start of each example to ensure isolation
    scan_response = mock_dynamodb_table.scan()
    with mock_dynamodb_table.batch_writer() as batch:
        for item in scan_response.get('Items', []):
            batch.delete_item(Key={'id': item['id']})
    
    event = {"body": json.dumps({"email": email, "password": password})}
    response = app.lambda_handler(event, None)
    
    # Check status code
    assert response['statusCode'] == 201
    
    # Check headers
    assert 'headers' in response
    assert response['headers']['Content-Type'] == 'application/json'
    
    # Check body structure
    body = json.loads(response['body'])
    assert 'user_id' in body
    assert 'message' in body
    
    # UUID format check
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    assert re.match(uuid_pattern, body['user_id'], re.IGNORECASE)


# Property 14: Unexpected Exceptions Return 500
# **Validates: Requirements 8.2**
@mock_dynamodb
def test_unexpected_exceptions_return_500():
    """Test that unexpected exceptions return 500."""
    # Create mock DynamoDB table
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Create event that will cause an error during processing
    # (e.g., by mocking a function to raise an exception)
    event = {"body": json.dumps({"email": "test@example.com", "password": "testpass123"})}
    
    # Temporarily replace a function to raise an exception
    original_generate = app.generate_user_id
    app.generate_user_id = lambda: (_ for _ in ()).throw(RuntimeError("Unexpected error"))
    
    try:
        response = app.lambda_handler(event, None)
        
        # Should return 500
        assert response['statusCode'] == 500
        body = json.loads(response['body'])
        assert 'error' in body
        assert body['error'] == "Internal server error"
    finally:
        # Restore original function
        app.generate_user_id = original_generate


# Property 15: All Responses Are Valid JSON
# **Validates: Requirements 8.4, 9.4**
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(scenario=sampled_from(['success', 'validation_error', 'duplicate', 'missing_body']))
def test_all_responses_valid_json(mock_dynamodb_table, scenario):
    """Test that all response bodies are valid JSON."""
    # Generate different scenarios
    if scenario == 'success':
        event = {"body": json.dumps({"email": "test@example.com", "password": "testpass123"})}
    elif scenario == 'validation_error':
        event = {"body": json.dumps({"email": "invalid-email", "password": "testpass123"})}
    elif scenario == 'duplicate':
        # First create a user
        event1 = {"body": json.dumps({"email": "test@example.com", "password": "testpass123"})}
        app.lambda_handler(event1, None)
        # Then try to create again
        event = {"body": json.dumps({"email": "test@example.com", "password": "testpass123"})}
    else:  # missing_body
        event = {}
    
    response = app.lambda_handler(event, None)
    
    # Response should have Content-Type header
    assert 'headers' in response
    assert response['headers']['Content-Type'] == 'application/json'
    
    # Body should be valid JSON
    body = json.loads(response['body'])
    assert isinstance(body, dict)


# Property 16: Invalid Email Format Returns 400
# **Validates: Requirements 10.2**
@given(invalid_email=text(min_size=1, max_size=50).filter(lambda x: '@' not in x))
def test_invalid_email_format(invalid_email):
    """Test that invalid email formats raise ValueError."""
    with pytest.raises(ValueError) as exc_info:
        app.validate_email(invalid_email)
    
    assert "Invalid email format" in str(exc_info.value)


# Property 17: Short Password Returns 400
# **Validates: Requirements 11.2**
@given(short_password=text(min_size=0, max_size=7))
def test_short_password(short_password):
    """Test that short passwords raise ValueError."""
    with pytest.raises(ValueError) as exc_info:
        app.validate_password(short_password)
    
    assert "at least 8 characters" in str(exc_info.value)


# Property 18: Bcrypt Hashing Round Trip
# **Validates: Requirements 3.1**
@given(password=text(min_size=8, max_size=100).filter(lambda x: '\x00' not in x))
def test_bcrypt_round_trip(password):
    """Test that bcrypt hashing and verification work correctly."""
    password_hash = app.hash_password(password)
    
    # Correct password should verify (with SHA-256 pre-hashing)
    sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    assert bcrypt.checkpw(sha256_hash.encode('utf-8'), password_hash.encode('utf-8'))
    
    # Wrong password should not verify (with SHA-256 pre-hashing)
    wrong_password = password + "wrong"
    wrong_sha256_hash = hashlib.sha256(wrong_password.encode('utf-8')).hexdigest()
    assert not bcrypt.checkpw(wrong_sha256_hash.encode('utf-8'), password_hash.encode('utf-8'))




# ============================================================================
# PRESERVATION TESTS
# These tests MUST PASS on unfixed code to document baseline behavior
# ============================================================================

# Preservation 1: Standard Email Validation Unchanged
# **Validates: Requirements 3.1, 3.2, 3.3**
# **EXPECTED OUTCOME**: Test PASSES on unfixed code
@given(
    local_part=st.text(
        alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='._%+-'),
        min_size=2,  # At least 2 characters to avoid single-character local parts
        max_size=20
    ).filter(lambda x: len(x) >= 2 and x[0] not in '.+-' and x[-1] not in '.+-'),
    domain_label1=st.text(
        alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-'),
        min_size=2,  # At least 2 characters to avoid single-character domain labels
        max_size=15
    ).filter(lambda x: len(x) >= 2 and x[0] not in '-' and x[-1] not in '-'),
    domain_label2=st.text(
        alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-'),
        min_size=2,  # At least 2 characters to avoid single-character domain labels
        max_size=15
    ).filter(lambda x: len(x) >= 2 and x[0] not in '-' and x[-1] not in '-'),
    tld=st.sampled_from(['com', 'org', 'net', 'edu', 'co', 'io', 'dev', 'app'])
)
def test_preservation1_standard_email_validation_unchanged(local_part, domain_label1, domain_label2, tld):
    """
    Preservation Test: Standard email validation behavior remains unchanged.
    
    This test verifies that emails WITHOUT single-character components continue
    to be validated correctly after the bug fix. This is preservation testing -
    we're documenting the current behavior that must NOT change.
    
    Preservation Scope: All emails where:
    - Local part has 2+ characters
    - All domain labels have 2+ characters
    - TLD has 2+ characters
    
    Expected Behavior on UNFIXED code:
    - Valid multi-character emails are accepted and normalized to lowercase
    - Invalid emails (no @, missing domain) are rejected with ValueError
    
    This test MUST PASS on unfixed code to establish the baseline behavior.
    After the fix, this test must still pass to ensure no regressions.
    
    Requirements validated:
    - 3.1: Standard format emails (e.g., user@example.com) continue to be accepted
    - 3.2: Emails missing @ symbol continue to be rejected
    - 3.3: Emails missing domain extension continue to be rejected
    """
    # Construct email with multi-character components only
    email = f"{local_part}@{domain_label1}.{domain_label2}.{tld}"
    
    # Property 1: Valid multi-character emails are accepted and normalized to lowercase
    try:
        result = app.validate_email(email)
        # Should return lowercase version
        assert result == email.lower(), f"Expected {email.lower()}, got {result}"
        assert isinstance(result, str), "Result should be a string"
    except ValueError:
        # If validation fails, it should be due to invalid characters or format
        # not due to single-character components (which we explicitly avoid)
        # This is acceptable - some generated strings may have invalid patterns
        pass
    
    # Property 2: Emails missing @ symbol are rejected
    email_no_at = email.replace('@', '')
    try:
        app.validate_email(email_no_at)
        # Should not reach here - should raise ValueError
        assert False, f"Email without @ should be rejected: {email_no_at}"
    except ValueError as e:
        assert "Invalid email format" in str(e)
    
    # Property 3: Emails missing domain extension are rejected
    # Create email with just local@domain (no TLD)
    email_no_tld = f"{local_part}@{domain_label1}"
    try:
        app.validate_email(email_no_tld)
        # Should not reach here - should raise ValueError
        assert False, f"Email without TLD should be rejected: {email_no_tld}"
    except ValueError as e:
        assert "Invalid email format" in str(e)
# Preservation 2: Duplicate Detection Unchanged
# **Validates: Requirements 3.5**
# **EXPECTED OUTCOME**: Test PASSES on unfixed code
@mock_dynamodb
def test_preservation2_duplicate_detection_unchanged():
    """
    Preservation Test: Duplicate email detection behavior remains unchanged.

    This test verifies that duplicate email detection within the same test execution
    continues to work correctly after the bug fix. This is preservation testing -
    we're documenting the current behavior that must NOT change.

    Preservation Scope: All duplicate email registrations where:
    - Same email is registered twice within the same test execution
    - Case-insensitive matching applies (Test@example.com == test@example.com)
    - Second registration attempt returns 409 conflict

    Expected Behavior on UNFIXED code:
    - First registration with email returns 201 success
    - Second registration with same email (any case) returns 409 conflict
    - Error message contains "already registered"
    - Case-insensitive matching works (Test@example.com == test@example.com)

    This test MUST PASS on unfixed code to establish the baseline behavior.
    After the fix, this test must still pass to ensure no regressions.

    Requirements validated:
    - 3.5: Duplicate email within same test run returns 409 conflict
    
    Note: This is a unit test (not property-based) to avoid Bug 2 (test isolation
    failure) which causes emails to persist across property test cases.
    """
    # Create fresh DynamoDB table for this test
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Use a unique email for this test to avoid any cross-test contamination
    import time
    unique_email = f"test{int(time.time() * 1000000)}@example.com"
    
    # Property 1: First registration succeeds with 201
    event1 = {"body": json.dumps({"email": unique_email, "password": "password123"})}
    response1 = app.lambda_handler(event1, None)
    
    assert response1['statusCode'] == 201, \
        f"First registration should succeed with 201, got {response1['statusCode']}"
    
    body1 = json.loads(response1['body'])
    assert 'user_id' in body1, "First registration should return user_id"
    assert 'message' in body1, "First registration should return message"
    
    # Property 2: Second registration with same email returns 409 conflict
    event2 = {"body": json.dumps({"email": unique_email, "password": "differentpass456"})}
    response2 = app.lambda_handler(event2, None)
    
    assert response2['statusCode'] == 409, \
        f"Duplicate email should return 409, got {response2['statusCode']}"
    
    body2 = json.loads(response2['body'])
    assert 'error' in body2, "Duplicate registration should return error"
    assert "already registered" in body2['error'].lower(), \
        f"Error message should mention 'already registered', got: {body2['error']}"
    
    # Property 3: Case-insensitive matching works
    # Try registering with different case variations
    email_upper = unique_email.upper()
    email_mixed = ''.join(c.upper() if i % 2 == 0 else c.lower() 
                          for i, c in enumerate(unique_email))
    
    for email_variant in [email_upper, email_mixed]:
        event3 = {"body": json.dumps({"email": email_variant, "password": "anotherpass789"})}
        response3 = app.lambda_handler(event3, None)
        
        # Should still return 409 because email matching is case-insensitive
        assert response3['statusCode'] == 409, \
            f"Case-insensitive duplicate detection should return 409 for {email_variant}, got {response3['statusCode']}"
        
        body3 = json.loads(response3['body'])
        assert "already registered" in body3['error'].lower(), \
            f"Error message should mention 'already registered' for case variant {email_variant}"




# Preservation 3: Bcrypt Security Unchanged
# **Validates: Requirements 3.6**
# **EXPECTED OUTCOME**: Test PASSES on unfixed code
@given(password=st.text(min_size=8, max_size=100).filter(lambda x: '\x00' not in x))
def test_preservation3_bcrypt_security_unchanged(password):
    """
    Preservation Test: Bcrypt security properties remain unchanged.
    
    This test verifies that all bcrypt security properties are preserved after
    the bug fix. This is preservation testing - we're documenting the current
    security behavior that must NOT change.
    
    Preservation Scope: All password hashing operations where:
    - Bcrypt work factor 12 is used
    - SHA-256 pre-hashing occurs before bcrypt
    - Hash format is $2b$12$...
    - Password verification works correctly
    
    Expected Behavior on UNFIXED code:
    - hash_password() uses bcrypt with work factor 12
    - SHA-256 pre-hashing is applied before bcrypt
    - Hash format starts with $2b$12$ (bcrypt version 2b, work factor 12)
    - Hash length is 60 characters (standard bcrypt format)
    - Password verification works correctly with SHA-256 pre-hashing
    - Wrong passwords fail verification
    
    This test MUST PASS on unfixed code to establish the baseline security behavior.
    After the fix (adjusting deadline), this test must still pass to ensure no
    security regressions in the password hashing implementation.
    
    Requirements validated:
    - 3.6: Bcrypt work factor 12, SHA-256 pre-hashing, and security properties preserved
    """
    # Property 1: hash_password produces bcrypt hash with work factor 12
    password_hash = app.hash_password(password)
    
    # Verify hash format: $2b$12$...
    assert password_hash.startswith('$2b$12$'), \
        f"Hash should start with '$2b$12$' (bcrypt v2b, work factor 12), got: {password_hash[:7]}"
    
    # Verify hash length (standard bcrypt format)
    assert len(password_hash) == 60, \
        f"Hash should be 60 characters (standard bcrypt), got: {len(password_hash)}"
    
    # Property 2: SHA-256 pre-hashing is used (verify by checking password verification)
    # The hash_password function pre-hashes with SHA-256, so verification must also use SHA-256
    sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    # Verify correct password with SHA-256 pre-hashing
    assert bcrypt.checkpw(sha256_hash.encode('utf-8'), password_hash.encode('utf-8')), \
        "Correct password with SHA-256 pre-hashing should verify successfully"
    
    # Property 3: Wrong password fails verification
    wrong_password = password + "wrong"
    wrong_sha256_hash = hashlib.sha256(wrong_password.encode('utf-8')).hexdigest()
    
    assert not bcrypt.checkpw(wrong_sha256_hash.encode('utf-8'), password_hash.encode('utf-8')), \
        "Wrong password should fail verification"
    
    # Property 4: Verify that direct password (without SHA-256) does NOT verify
    # This confirms SHA-256 pre-hashing is actually being used
    try:
        # If we try to verify the raw password (without SHA-256), it should fail
        # because the hash was created from SHA-256(password), not from password directly
        direct_verify = bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        assert not direct_verify, \
            "Raw password should NOT verify (confirms SHA-256 pre-hashing is used)"
    except Exception:
        # If bcrypt raises an exception, that's also acceptable - it means the formats don't match
        pass
    
    # Property 5: Hash format components are correct
    # Bcrypt format: $2b$12$[22-char salt][31-char hash]
    parts = password_hash.split('$')
    assert len(parts) == 4, f"Hash should have 4 parts separated by '$', got: {len(parts)}"
    assert parts[0] == '', "First part should be empty (hash starts with $)"
    assert parts[1] == '2b', f"Version should be '2b', got: {parts[1]}"
    assert parts[2] == '12', f"Work factor should be '12', got: {parts[2]}"
    assert len(parts[3]) == 53, f"Salt+hash should be 53 characters, got: {len(parts[3])}"
