#!/usr/bin/env python3
"""
void_key.py - Secure decryption utility for Void Scribe encrypted files.
Supports both legacy (SHA-256) and new (PBKDF2HMAC) encryption formats.
"""

import argparse
import getpass
import sys
import os
import void_core


def detect_encryption_format(data: bytes) -> str:
    """
    Detect whether file uses legacy or new encryption format.
    
    Args:
        data: Raw encrypted file data
        
    Returns:
        'legacy' for old SHA-256 format, 'new' for PBKDF2HMAC format
    """
    # New format: salt (16 bytes) + nonce (12 bytes) + ciphertext
    # Legacy format: nonce (12 bytes) + ciphertext
    # We can distinguish by checking if we have enough bytes for salt + nonce
    if len(data) >= 28:  # 16 (salt) + 12 (nonce) minimum
        return 'new'
    elif len(data) >= 12:  # 12 (nonce) minimum
        return 'legacy'
    else:
        return 'invalid'


def decrypt_legacy_format(data: bytes, password: str) -> bytes:
    """
    Decrypt using legacy SHA-256 key derivation (for backward compatibility).
    
    Args:
        data: Encrypted data in legacy format
        password: Decryption password
        
    Returns:
        Decrypted plaintext bytes
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import hashlib
    
    if len(data) < 12:
        raise ValueError("File too short for legacy format")
    
    nonce = data[:12]
    ciphertext = data[12:]
    
    # Legacy key derivation (insecure, but needed for compatibility)
    key = hashlib.sha256(password.encode()).digest()
    
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def decrypt_file_content(filepath: str, password: str, force_format: str = None) -> str:
    """
    Decrypt file content and return as string.
    
    Args:
        filepath: Path to encrypted file
        password: Decryption password
        force_format: Force specific format ('legacy' or 'new'), None for auto-detect
        
    Returns:
        Decrypted content as string
        
    Raises:
        Various exceptions for file/decryption errors
    """
    try:
        data = void_core.load_inscription(filepath)
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")
    except Exception as e:
        raise Exception(f"Failed to read file: {e}")
    
    # Determine encryption format
    if force_format:
        format_type = force_format
    else:
        format_type = detect_encryption_format(data)
        
    if format_type == 'invalid':
        raise ValueError("File too short to contain valid encrypted data")
    
    # Attempt decryption
    try:
        if format_type == 'legacy':
            print("[INFO] Detected legacy encryption format (less secure)")
            decrypted_bytes = decrypt_legacy_format(data, password)
        else:  # new format
            decrypted_bytes = void_core.decrypt_content(data, password)
            
        # Convert to string
        try:
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Decrypted content is not valid UTF-8 text")
            
    except Exception as e:
        # If auto-detection failed, try the other format
        if not force_format and format_type == 'new':
            try:
                print("[INFO] New format failed, trying legacy format...")
                decrypted_bytes = decrypt_legacy_format(data, password)
                return decrypted_bytes.decode('utf-8')
            except:
                pass  # Fall through to original error
        
        raise Exception(f"Decryption failed - wrong password or corrupted data: {e}")


def prompt_password():
    """
    Securely prompt for password.
    
    Returns:
        Password string
    """
    password = getpass.getpass("Enter decryption password: ")
    if not password:
        raise ValueError("Password cannot be empty")
    return password


def main():
    parser = argparse.ArgumentParser(
        description="Void Key: Decrypt .enc files created by Void Scribe",
        epilog="Supports both legacy (SHA-256) and new (PBKDF2HMAC) encryption formats."
    )
    parser.add_argument('file', help="Path to the encrypted .enc file")
    parser.add_argument('--format', choices=['legacy', 'new'],
                       help="Force specific encryption format (default: auto-detect)")
    parser.add_argument('--output', '-o', help="Save decrypted content to file instead of displaying")
    parser.add_argument('--quiet', '-q', action='store_true',
                       help="Suppress informational messages")
    
    args = parser.parse_args()
    
    # Validate file exists
    if not os.path.isfile(args.file):
        print(f"[ERROR] File not found: {args.file}")
        sys.exit(1)
    
    try:
        # Get password
        password = prompt_password()
        
        # Decrypt file
        content = decrypt_file_content(args.file, password, args.format)
        
        # Output content
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(content)
                if not args.quiet:
                    print(f"[SUCCESS] Decrypted content saved to: {args.output}")
            except Exception as e:
                print(f"[ERROR] Failed to save output file: {e}")
                sys.exit(1)
        else:
            # Display content
            if not args.quiet:
                print("\n" + "="*50)
                print("DECRYPTED CONTENT")
                print("="*50 + "\n")
            
            print(content)
            
            if not args.quiet:
                print("\n" + "="*50)
                print(f"Successfully decrypted {len(content)} characters")
                print("="*50)
        
    except KeyboardInterrupt:
        print("\n[CANCELLED] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
