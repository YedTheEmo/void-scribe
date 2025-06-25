#!/usr/bin/env python3
"""
Void Scribe Terminal: A minimal console text editor that conceals all input
and saves your hidden notes upon interruption.

Enhanced with secure encryption, remote sending, and local deletion.
Perfect for public writing where prying eyes must see nothing.
"""

import sys
import termios
import argparse
import getpass
import void_core


def prompt_password(confirm=False):
    """
    Prompts for password with optional confirmation.
    
    Args:
        confirm: Whether to ask for password confirmation
        
    Returns:
        Validated password string
    """
    while True:
        pwd = getpass.getpass("Enter password: ")
        is_valid, error_msg = void_core.validate_password(pwd)
        
        if not is_valid:
            print(f"[Error] {error_msg}")
            continue
            
        if confirm:
            pwd2 = getpass.getpass("Confirm password: ")
            if pwd != pwd2:
                print("[Error] Passwords do not match. Try again.")
                continue
                
        return pwd


def setup_terminal():
    """
    Sets up terminal for hidden input (no echo).
    
    Returns:
        Tuple of (file_descriptor, original_settings)
    """
    fd = sys.stdin.fileno()
    original = termios.tcgetattr(fd)
    occult = termios.tcgetattr(fd)
    occult[3] &= ~termios.ECHO  # Disable echo
    
    termios.tcsetattr(fd, termios.TCSADRAIN, occult)
    return fd, original


def restore_terminal(fd, original_settings):
    """
    Restores terminal to original settings.
    
    Args:
        fd: File descriptor
        original_settings: Original terminal settings
    """
    termios.tcsetattr(fd, termios.TCSADRAIN, original_settings)


def collect_input():
    """
    Collects user input until Ctrl+C is pressed.
    
    Returns:
        List of input lines
    """
    incantation = []
    print("[==> Entering Void Scribe: your keystrokes are unseen, interrupt with Ctrl+C to inscribe your scripture <==]")
    
    try:
        while True:
            line = sys.stdin.readline()
            if not line:  # EOF
                break
            incantation.append(line)
    except KeyboardInterrupt:
        # Expected way to finish input
        pass
    
    return incantation


def main():
    parser = argparse.ArgumentParser(
        description="Void Scribe Terminal: Concealed text editor with encryption and remote sending."
    )
    parser.add_argument('--encrypt', action='store_true',
                       help="Encrypt the content before saving")
    parser.add_argument('--send', action='store_true',
                       help="Send the saved file to a remote server via SCP")
    parser.add_argument('--delete-local', action='store_true',
                       help="Delete the local file after saving (and sending if enabled)")
    parser.add_argument('--server', type=str,
                       help="Remote server address for sending (required if --send)")
    parser.add_argument('--remote-path', type=str, default='~/',
                       help="Remote path on server (default: ~/)")
    parser.add_argument('--verbose', action='store_true',
                       help="Enable verbose output")
    parser.add_argument('--filename', type=str,
                       help="Custom filename (default: auto-generated with timestamp)")
    
    args = parser.parse_args()
    
    # Validation
    if args.send and not args.server:
        print("[Error] --server must be specified when using --send")
        sys.exit(1)
    
    # Check if termios is available (Unix-like systems only)
    try:
        fd, original = setup_terminal()
    except Exception as e:
        print(f"[Error] This terminal version requires a Unix-like system: {e}")
        print("Consider using the GUI version (void_scribe_gui.py) for cross-platform support.")
        sys.exit(1)
    
    try:
        # Collect hidden input
        incantation = collect_input()
        
        # Convert to bytes
        content_str = ''.join(incantation)
        content_bytes = content_str.encode('utf-8')
        
        if not content_bytes.strip():
            print("\n[Warning] No content to save.")
            return
        
        # Encryption step
        if args.encrypt:
            if args.verbose:
                print("\n[Encryption enabled]")
            password = prompt_password(confirm=True)
            try:
                content_bytes = void_core.encrypt_content(content_bytes, password)
                if args.verbose:
                    print("[Content encrypted successfully]")
            except Exception as e:
                print(f"\n[Error] Encryption failed: {e}")
                return
        
        # Generate filename
        filename = args.filename or void_core.generate_filename(encrypted=args.encrypt)
        
        # Save file
        saved = void_core.save_inscription(content_bytes, filename, verbose=args.verbose)
        if not saved:
            print("[Error] Failed to save file")
            return
        
        # Remote send step
        if args.send:
            if args.verbose:
                print("[Initiating remote send]")
            success = void_core.send_to_remote(
                filename, args.server, args.remote_path, verbose=args.verbose
            )
            if not success:
                print("[Warning] Remote send failed")
        
        # Delete local file if requested
        if args.delete_local:
            void_core.delete_local_file(filename, verbose=args.verbose)
            
    finally:
        # Always restore terminal settings
        restore_terminal(fd, original)


if __name__ == '__main__':
    main()
