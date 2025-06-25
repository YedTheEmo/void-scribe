#!/usr/bin/env python3
"""
void_core.py - Core functionality for Void Scribe encryption/decryption system.
Provides secure AES-256-GCM encryption with proper key derivation using PBKDF2HMAC.
"""

import os
import subprocess
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Security constants
SALT_SIZE = 16  # 128-bit salt
ITERATIONS = 100000  # PBKDF2 iterations (adjust based on performance requirements)
KEY_SIZE = 32  # 256-bit key for AES-256


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a cryptographic key from password using PBKDF2HMAC.
    This is much more secure than direct SHA-256 hashing.
    
    Args:
        password: User's password string
        salt: Unique random salt for this encryption
        
    Returns:
        32-byte derived key for AES-256
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_content(content: bytes, password: str) -> bytes:
    """
    Encrypts content using AES-256-GCM with proper key derivation.
    
    Format: salt (16 bytes) + nonce (12 bytes) + ciphertext + auth_tag
    
    Args:
        content: Raw bytes to encrypt
        password: User's password
        
    Returns:
        Encrypted data with salt and nonce prepended
    """
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    
    encrypted_data = aesgcm.encrypt(nonce, content, None)
    
    # Combine salt + nonce + encrypted_data for storage
    return salt + nonce + encrypted_data


def decrypt_content(encrypted_data_with_meta: bytes, password: str) -> bytes:
    """
    Decrypts content encrypted with encrypt_content().
    
    Args:
        encrypted_data_with_meta: Combined salt + nonce + ciphertext + tag
        password: User's password
        
    Returns:
        Decrypted plaintext bytes
        
    Raises:
        ValueError: If data format is invalid
        Exception: If decryption fails (wrong password or corrupted data)
    """
    if len(encrypted_data_with_meta) < SALT_SIZE + 12:
        raise ValueError("Encrypted data too short to contain salt and nonce")
    
    # Extract components
    salt = encrypted_data_with_meta[:SALT_SIZE]
    nonce = encrypted_data_with_meta[SALT_SIZE:SALT_SIZE + 12]
    ciphertext = encrypted_data_with_meta[SALT_SIZE + 12:]
    
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    return aesgcm.decrypt(nonce, ciphertext, None)


def save_inscription(content: bytes, filename: str, verbose: bool = True) -> bool:
    """
    Saves content to file.
    
    Args:
        content: Bytes to save
        filename: Target file path
        verbose: Whether to print status messages
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(filename, 'wb') as f:
            f.write(content)
        if verbose:
            print(f"[Enscribed {len(content)} bytes into '{filename}']")
        return True
    except Exception as e:
        if verbose:
            print(f"[Error during inscription: {e}]")
        return False


def load_inscription(filename: str) -> bytes:
    """
    Loads content from file.
    
    Args:
        filename: Source file path
        
    Returns:
        File content as bytes
        
    Raises:
        FileNotFoundError: If file doesn't exist
        Exception: If read fails
    """
    with open(filename, 'rb') as f:
        return f.read()


def generate_filename(encrypted: bool = False, timestamp: str = None) -> str:
    """
    Generates a timestamped filename.
    
    Args:
        encrypted: Whether file will be encrypted (.enc vs .txt)
        timestamp: Custom timestamp string, or None for current time
        
    Returns:
        Generated filename
    """
    if timestamp is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    suffix = '.enc' if encrypted else '.txt'
    return f"scripture_{timestamp}{suffix}"


def send_to_remote(filename: str, server: str, remote_path: str, verbose: bool = False) -> bool:
    """
    Sends file to remote server via SCP.
    
    Args:
        filename: Local file to send
        server: Remote server address
        remote_path: Remote destination path
        verbose: Whether to print status messages
        
    Returns:
        True if successful, False otherwise
    """
    remote_target = f"{server}:{remote_path}"
    cmd = ['scp', filename, remote_target]
    
    if verbose:
        print(f"[Sending '{filename}' to '{server}:{remote_path}']")
    
    try:
        subprocess.run(cmd, check=True, capture_output=not verbose)
        if verbose:
            print("[Remote send successful]")
        return True
    except subprocess.CalledProcessError as e:
        if verbose:
            print(f"[Error sending to remote: {e}]")
        return False
    except FileNotFoundError:
        if verbose:
            print("[Error: scp command not found]")
        return False


def delete_local_file(filename: str, verbose: bool = False) -> bool:
    """
    Deletes a local file.
    
    Args:
        filename: File to delete
        verbose: Whether to print status messages
        
    Returns:
        True if successful, False otherwise
    """
    try:
        os.remove(filename)
        if verbose:
            print(f"[Local file '{filename}' deleted]")
        return True
    except Exception as e:
        if verbose:
            print(f"[Error deleting file: {e}]")
        return False


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validates password strength.
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not password:
        return False, "Password cannot be empty"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    return True, ""
