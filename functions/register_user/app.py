"""
User registration Lambda function.

This module handles user registration requests, validates input,
hashes passwords, and stores user records in DynamoDB.
"""

import bcrypt
import boto3
from datetime import datetime, timezone
import hashlib
import json
import logging
import re
import traceback
import uuid
from typing import Any, Dict


# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class DuplicateEmailError(Exception):
    """Raised when email address already exists in database."""
    pass


def validate_request_body(event: dict) -> Dict[str, str]:
    """
    Extract and validate JSON body from API Gateway event.
    
    Args:
        event: API Gateway event dict
        
    Returns:
        Dict containing email and password fields
        
    Raises:
        ValueError: If body is missing, invalid JSON, or missing required fields
    """
    # Check for request body
    body_str = event.get("body")
    if not body_str:
        raise ValueError("Request body is required")
    
    # Parse JSON
    try:
        body = json.loads(body_str)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON in request body")
    
    # Check for required fields
    if "email" not in body:
        raise ValueError("Missing required field: email")
    if "password" not in body:
        raise ValueError("Missing required field: password")
    
    return {
        "email": body["email"],
        "password": body["password"]
    }


def validate_email(email: str) -> str:
    """
    Validate email format and normalize to lowercase.
    
    Args:
        email: Email address to validate
        
    Returns:
        Lowercase email address
        
    Raises:
        ValueError: If email format is invalid
    """
    # Email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(pattern, email):
        raise ValueError("Invalid email format")
    
    # Return lowercase for case-insensitive storage
    return email.lower()


def validate_password(password: str) -> None:
    """
    Validate password meets minimum strength requirements.
    
    Args:
        password: Password to validate
        
    Raises:
        ValueError: If password is too short
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")


def generate_user_id() -> str:
    """
    Generate unique user ID using UUID version 4.
    
    Returns:
        UUID string in format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    """
    return str(uuid.uuid4())


def hash_password(password: str) -> str:
    """
    Hash password using bcrypt with default work factor (12).
    
    Pre-hashes password with SHA-256 before bcrypt to normalize input length
    and eliminate bcrypt's 72-byte truncation vulnerability.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        Bcrypt hash string in format $2b$12$...
    """
    # Pre-hash with SHA-256 to normalize input length
    # This eliminates bcrypt's 72-byte truncation vulnerability
    sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    # Generate salt and hash the SHA-256 digest with bcrypt
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(sha256_hash.encode('utf-8'), salt)
    
    # Decode bytes to string for DynamoDB storage
    return hashed.decode('utf-8')


def check_duplicate_email(email: str, table_name: str) -> bool:
    """
    Check if email already exists in Users table.
    
    Note: This implementation uses table scan for simplicity.
    For production workloads, add a Global Secondary Index (GSI)
    with email as the partition key for better performance.
    
    Args:
        email: Email address to check (should be lowercase)
        table_name: Name of the DynamoDB table
        
    Returns:
        True if email exists, False otherwise
    """
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)
    
    try:
        # Scan table for matching email
        # Note: Using scan is acceptable for low volume, but GSI recommended for production
        response = table.scan(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        
        # Return True if any items found
        return len(response.get('Items', [])) > 0
        
    except Exception as e:
        logger.error(f"DynamoDB read error during duplicate check: {str(e)}")
        raise


def create_user_record(user_id: str, email: str, password_hash: str) -> Dict[str, str]:
    """
    Create user record dictionary with all required attributes.
    
    Args:
        user_id: Unique user identifier (UUID)
        email: User's email address (lowercase)
        password_hash: Bcrypt hash of user's password
        
    Returns:
        Dict containing user record with id, email, password_hash, and created_at
    """
    # Generate ISO 8601 timestamp in UTC
    timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    # Create user record with lowercase snake_case attributes
    return {
        'id': user_id,
        'email': email,
        'password_hash': password_hash,
        'created_at': timestamp
    }


def store_user(user_record: Dict[str, str], table_name: str) -> None:
    """
    Write user record to DynamoDB Users table.
    
    Args:
        user_record: User record dict with id, email, password_hash, created_at
        table_name: Name of the DynamoDB table
        
    Raises:
        Exception: If DynamoDB write operation fails
    """
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)
    
    try:
        table.put_item(Item=user_record)
    except Exception as e:
        logger.error(f"DynamoDB write error: {str(e)}")
        raise


def lambda_handler(event: dict, context: Any) -> dict:
    """
    Handle user registration requests.
    
    Validates input, checks for duplicate emails, hashes password,
    and stores user record in DynamoDB.
    
    Args:
        event: API Gateway event containing request body with email and password
        context: Lambda context object with runtime information
        
    Returns:
        API Gateway response dict with statusCode, headers, and body
    """
    try:
        # Extract and validate request body
        body = validate_request_body(event)
        email = body['email']
        password = body['password']
        
        # Validate email format and normalize to lowercase
        email = validate_email(email)
        
        # Validate password strength
        validate_password(password)
        
        # Check for duplicate email
        if check_duplicate_email(email, 'Users'):
            raise DuplicateEmailError("Email address already registered")
        
        # Generate unique user ID
        user_id = generate_user_id()
        
        # Hash password securely
        password_hash = hash_password(password)
        
        # Create user record
        user_record = create_user_record(user_id, email, password_hash)
        
        # Store user in DynamoDB
        store_user(user_record, 'Users')
        
        # Log successful registration (user_id only, no sensitive data)
        logger.info(f"User registered successfully: {user_id}")
        
        # Return success response
        return create_response(201, {
            "message": "User registered successfully",
            "user_id": user_id
        })
        
    except ValueError as e:
        # Client errors - validation failures
        logger.error(f"Validation error: {str(e)}")
        return create_response(400, {"error": str(e)})
        
    except DuplicateEmailError as e:
        # Conflict errors - email already exists
        logger.error(f"Duplicate email error: {str(e)}")
        return create_response(409, {"error": str(e)})
        
    except Exception as e:
        # Unexpected errors - log and return generic message
        logger.error(f"Unexpected error: {str(e)}")
        traceback.print_exc()
        return create_response(500, {"error": "Internal server error"})


def create_response(status_code: int, body: Dict[str, Any]) -> dict:
    """
    Create standardized API Gateway response.
    
    Args:
        status_code: HTTP status code
        body: Response body dictionary
        
    Returns:
        API Gateway response dict with statusCode, headers, and body
    """
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body)
    }
