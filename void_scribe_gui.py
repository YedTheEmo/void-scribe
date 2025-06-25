#!/usr/bin/env python3
"""
Void Scribe GUI: A Notepad-like text editor with secure encryption capabilities.
Cross-platform GUI version of Void Scribe using Tkinter.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import void_core
import os
from datetime import datetime

class PrivateText(tk.Text):
    """Text widget that shows asterisks while maintaining actual text."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.actual_text = ""
        self.privacy_mode = False
        self.bind('<Key>', self._on_key)
        self.bind('<BackSpace>', self._on_backspace)
        self.bind('<Delete>', self._on_delete)

    def _on_key(self, event):
        if not self.privacy_mode or not event.char:
            return
        # Insert actual character but show asterisk
        pos = self.index(tk.INSERT)
        self.actual_text = self.actual_text[:self._pos_to_index(pos)] + event.char + self.actual_text[self._pos_to_index(pos):]
        self._update_display()
        return "break"  # Prevent default insertion

    def _on_backspace(self, event):
        if not self.privacy_mode:
            return
        pos = self.index(tk.INSERT)
        if pos != "1.0":
            self.actual_text = self.actual_text[:self._pos_to_index(pos)-1] + self.actual_text[self._pos_to_index(pos):]
            self._update_display()
        return "break"

    def _on_delete(self, event):
        if not self.privacy_mode:
            return
        pos = self.index(tk.INSERT)
        if pos != self.index(tk.END):
            self.actual_text = self.actual_text[:self._pos_to_index(pos)] + self.actual_text[self._pos_to_index(pos)+1:]
            self._update_display()
        return "break"

    def _pos_to_index(self, pos):
        """Convert tkinter position to string index."""
        line, col = map(int, pos.split('.'))
        return (line-1)*1000 + col  # Approximate for simplicity

    def _update_display(self):
        """Update visible text with asterisks."""
        self.delete(1.0, tk.END)
        self.insert(1.0, "*" * len(self.actual_text))

    def get_actual_text(self):
        """Get the actual text content."""
        return self.actual_text if self.privacy_mode else self.get(1.0, tk.END)

    def set_privacy_mode(self, enabled):
        """Toggle privacy mode."""
        self.privacy_mode = enabled
        if enabled:
            self.actual_text = self.get(1.0, tk.END)
            self._update_display()
        else:
            self.delete(1.0, tk.END)
            self.insert(1.0, self.actual_text)


class PasswordDialog:
    """Custom password dialog with confirmation option."""
    
    def __init__(self, parent, title="Enter Password", confirm=False):
        self.result = None
        self.confirm = confirm
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x200")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (
            parent.winfo_rootx() + 50,
            parent.winfo_rooty() + 50
        ))
        
        self.create_widgets()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Password field with toggle
        pass_frame = ttk.Frame(main_frame)
        pass_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(pass_frame, text="Password:").pack(anchor=tk.W, pady=(0, 5))
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(pass_frame, textvariable=self.password_var, 
                                      show="*", width=35)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.show_pass = tk.BooleanVar(value=False)
        ttk.Button(pass_frame, text="👁", width=3, 
                  command=lambda: self.toggle_password_visibility(self.password_entry)).pack(side=tk.RIGHT)
        
        # Confirmation field (if needed)
        if self.confirm:
            confirm_frame = ttk.Frame(main_frame)
            confirm_frame.pack(fill=tk.X, pady=(0, 10))
            
            ttk.Label(confirm_frame, text="Confirm Password:").pack(anchor=tk.W, pady=(0, 5))
            
            self.confirm_var = tk.StringVar()
            self.confirm_entry = ttk.Entry(confirm_frame, textvariable=self.confirm_var,
                                         show="*", width=35)
            self.confirm_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            ttk.Button(confirm_frame, text="👁", width=3,
                      command=lambda: self.toggle_password_visibility(self.confirm_entry)).pack(side=tk.RIGHT)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(button_frame, text="Cancel", command=self.cancel).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="OK", command=self.ok).pack(side=tk.RIGHT)
        
        # Bind Enter key
        self.dialog.bind('<Return>', lambda e: self.ok())
        self.dialog.bind('<Escape>', lambda e: self.cancel())
        
        # Focus on password field
        self.password_entry.focus_set()
        
    def ok(self):
        password = self.password_var.get()
        
        # Validate password
        is_valid, error_msg = void_core.validate_password(password)
        if not is_valid:
            messagebox.showerror("Invalid Password", error_msg, parent=self.dialog)
            return
            
        # Check confirmation if required
        if self.confirm:
            confirm_password = self.confirm_var.get()
            if password != confirm_password:
                messagebox.showerror("Password Mismatch", 
                                   "Passwords do not match", parent=self.dialog)
                return
        
        self.result = password
        self.dialog.destroy()
        
    def toggle_password_visibility(self, entry):
        """Toggle between showing password text and hiding it."""
        current_show = entry.cget('show')
        entry.config(show='' if current_show == '*' else '*')
        
    def cancel(self):
        self.dialog.destroy()


class VoidScribeGUI:
    """Main GUI application class."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Void Scribe - Secure Text Editor")
        self.root.geometry("800x600")
        
        # Application state
        self.current_file = None
        self.is_encrypted = False
        self.modified = False
        
        self.create_widgets()
        self.create_menu()
        
        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def create_widgets(self):
        """Create the main UI widgets."""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Toolbar
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(toolbar, text="New", command=self.new_file, width=8).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(toolbar, text="Open", command=self.open_file, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Save", command=self.save_file, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Save As", command=self.save_as_file, width=8).pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        
        ttk.Button(toolbar, text="Encrypt & Save", command=self.encrypt_save, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Decrypt", command=self.decrypt_file, width=8).pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        self.privacy_mode = False
        self.privacy_btn = ttk.Button(toolbar, text="🔒", command=self.toggle_privacy_mode, width=3)
        self.privacy_btn.pack(side=tk.LEFT, padx=2)
        
        # Status bar frame
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Text area with scrollbars
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create text widget with scrollbars
        self.text_area = PrivateText(text_frame, wrap=tk.WORD, undo=True, font=("Consolas", 11))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.text_area.yview)
        h_scrollbar = ttk.Scrollbar(text_frame, orient=tk.HORIZONTAL, command=self.text_area.xview)
        
        self.text_area.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack scrollbars and text area
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        # Bind text changes
        self.text_area.bind('<Control-s>', lambda e: self.save_file())
        self.text_area.bind('<Control-o>', lambda e: self.open_file())
        self.text_area.bind('<Control-n>', lambda e: self.new_file())
        
    def create_menu(self):
        """Create the application menu."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New", command=self.new_file, accelerator="Ctrl+N")
        file_menu.add_command(label="Open...", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Save", command=self.save_file, accelerator="Ctrl+S")
        file_menu.add_command(label="Save As...", command=self.save_as_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # Crypto menu
        crypto_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Crypto", menu=crypto_menu)
        crypto_menu.add_command(label="Encrypt & Save", command=self.encrypt_save)
        crypto_menu.add_command(label="Decrypt File...", command=self.decrypt_file)
        crypto_menu.add_separator()
        crypto_menu.add_command(label="Export Encrypted...", command=self.export_encrypted)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        
    def on_text_modified(self, event=None):
        """Handle text modification events."""
        if self.text_area.edit_modified():
            self.modified = True
            self.update_title()
            self.text_area.edit_modified(False)
            
    def update_title(self):
        """Update window title based on current state."""
        title = "Void Scribe"
        if self.current_file:
            filename = os.path.basename(self.current_file)
            title = f"{filename} - {title}"
        if self.modified:
            title = f"*{title}"
        if self.is_encrypted:
            title = f"{title} [ENCRYPTED]"
        if self.privacy_mode:
            title = f"{title} [PRIVATE]"
            
        self.root.title(title)
        
    def update_status(self, message):
        """Update status bar message."""
        if self.privacy_mode:
            self.status_var.set("Privacy mode active - text hidden")
        else:
            self.status_var.set(message)
        self.root.update_idletasks()

    def toggle_privacy_mode(self):
        """Toggle privacy mode to hide/show text content."""
        self.privacy_mode = not self.privacy_mode
        self.text_area.set_privacy_mode(self.privacy_mode)
        self.privacy_btn.config(text="🔓" if self.privacy_mode else "🔒")
        self.update_title()
        self.update_status("")
        
    def new_file(self):
        """Create a new file."""
        if self.check_save_changes():
            self.text_area.delete(1.0, tk.END)
            self.current_file = None
            self.is_encrypted = False
            self.modified = False
            self.update_title()
            self.update_status("New file created")
            
    def open_file(self):
        """Open a file."""
        if not self.check_save_changes():
            return
            
        filename = filedialog.askopenfilename(
            title="Open File",
            filetypes=[
                ("Text files", "*.txt"),
                ("Encrypted files", "*.enc"),
                ("All files", "*.*")
            ]
        )
        
        if not filename:
            return
            
        try:
            if filename.endswith('.enc'):
                self.open_encrypted_file(filename)
            else:
                self.open_plain_file(filename)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file:\n{str(e)}")
            
    def open_plain_file(self, filename):
        """Open a plain text file."""
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
            
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(1.0, content)
        
        self.current_file = filename
        self.is_encrypted = False
        self.modified = False
        self.update_title()
        self.update_status(f"Opened: {os.path.basename(filename)}")
        
    def open_encrypted_file(self, filename):
        """Open and decrypt an encrypted file."""
        dialog = PasswordDialog(self.root, "Enter Decryption Password")
        self.root.wait_window(dialog.dialog)
        
        if not dialog.result:
            return
            
        try:
            encrypted_data = void_core.load_inscription(filename)
            decrypted_data = void_core.decrypt_content(encrypted_data, dialog.result)
            content = decrypted_data.decode('utf-8')
            
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(1.0, content)
            
            self.current_file = filename
            self.is_encrypted = True
            self.modified = False
            self.update_title()
            self.update_status(f"Decrypted and opened: {os.path.basename(filename)}")
            
        except Exception as e:
            messagebox.showerror("Decryption Error", 
                               f"Failed to decrypt file. Wrong password or corrupted data:\n{str(e)}")
            
    def save_file(self):
        """Save the current file."""
        if self.current_file:
            if self.is_encrypted:
                # Re-encrypt with same password
                dialog = PasswordDialog(self.root, "Enter Password to Re-encrypt")
                self.root.wait_window(dialog.dialog)
                
                if not dialog.result:
                    return False
                    
                return self.save_encrypted_file(self.current_file, dialog.result)
            else:
                return self.save_plain_file(self.current_file)
        else:
            return self.save_as_file()
            
    def save_as_file(self):
        """Save file with a new name."""
        filename = filedialog.asksaveasfilename(
            title="Save As",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if not filename:
            return False
            
        if self.save_plain_file(filename):
            self.current_file = filename
            self.is_encrypted = False
            return True
        return False
        
    def save_plain_file(self, filename):
        """Save as plain text file."""
        try:
            content = self.text_area.get_actual_text().strip()  # Get actual content even in privacy mode
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
                
            self.modified = False
            self.update_title()
            self.update_status(f"Saved: {os.path.basename(filename)}")
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file:\n{str(e)}")
            return False
            
    def save_encrypted_file(self, filename, password):
        """Save as encrypted file."""
        try:
            content = self.text_area.get_actual_text().strip()
            content_bytes = content.encode('utf-8')
            encrypted_data = void_core.encrypt_content(content_bytes, password)
            
            if void_core.save_inscription(encrypted_data, filename, verbose=False):
                self.modified = False
                self.update_title()
                self.update_status(f"Encrypted and saved: {os.path.basename(filename)}")
                return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt and save file:\n{str(e)}")
        return False
        
    def encrypt_save(self):
        """Encrypt and save the current content."""
        dialog = PasswordDialog(self.root, "Encrypt File", confirm=True)
        self.root.wait_window(dialog.dialog)
        
        if not dialog.result:
            return
            
        # Generate encrypted filename
        if self.current_file:
            base_name = os.path.splitext(os.path.basename(self.current_file))[0]
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{base_name}_{timestamp}.enc"
        else:
            filename = void_core.generate_filename(encrypted=True)
            
        filename = filedialog.asksaveasfilename(
            title="Save Encrypted File",
            initialfile=filename,
            defaultextension=".enc",
            filetypes=[
                ("Encrypted files", "*.enc"),
                ("All files", "*.*")
            ]
        )
        
        if filename and self.save_encrypted_file(filename, dialog.result):
            self.current_file = filename
            self.is_encrypted = True
            
    def decrypt_file(self):
        """Decrypt a file and display its contents."""
        filename = filedialog.askopenfilename(
            title="Open Encrypted File",
            filetypes=[
                ("Encrypted files", "*.enc"),
                ("All files", "*.*")
            ]
        )
        
        if not filename:
            return
            
        # Check if we need to save current changes
        if not self.check_save_changes():
            return
            
        self.open_encrypted_file(filename)
        
    def export_encrypted(self):
        """Export current content as encrypted file without changing current file."""
        if not self.text_area.get_actual_text().strip():
            messagebox.showwarning("No Content", "No content to encrypt")
            return
            
        dialog = PasswordDialog(self.root, "Export Encrypted", confirm=True)
        self.root.wait_window(dialog.dialog)
        
        if not dialog.result:
            return
            
        filename = filedialog.asksaveasfilename(
            title="Export Encrypted File",
            initialfile=void_core.generate_filename(encrypted=True),
            defaultextension=".enc",
            filetypes=[
                ("Encrypted files", "*.enc"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                content = self.text_area.get_actual_text().strip()
                content_bytes = content.encode('utf-8')
                encrypted_data = void_core.encrypt_content(content_bytes, dialog.result)
                
                if void_core.save_inscription(encrypted_data, filename, verbose=False):
                    self.update_status(f"Exported encrypted: {os.path.basename(filename)}")
                    messagebox.showinfo("Export Successful", 
                                      f"File encrypted and saved as:\n{filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export encrypted file:\n{str(e)}")
                
    def check_save_changes(self):
        """Check if current file has unsaved changes and prompt to save."""
        if not self.modified:
            return True
            
        result = messagebox.askyesnocancel(
            "Unsaved Changes",
            "The current file has unsaved changes. Do you want to save them?"
        )
        
        if result is None:  # Cancel
            return False
        elif result:  # Yes, save
            return self.save_file()
        else:  # No, don't save
            return True
            
    def on_closing(self):
        """Handle application close event."""
        if self.check_save_changes():
            self.root.destroy()
            
    def show_about(self):
        """Show about dialog."""
        about_text = """Void Scribe GUI v2.0
        
A secure text editor with AES-256-GCM encryption.

Features:
• Cross-platform GUI interface
• Secure password-based encryption (PBKDF2HMAC)
• Standard text editing capabilities
• Import/export encrypted files
• Compatible with terminal version

Created for secure note-taking and confidential writing."""
        
        messagebox.showinfo("About Void Scribe", about_text)
        
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def main():
    """Main entry point for GUI application."""
    try:
        app = VoidScribeGUI()
        app.run()
    except Exception as e:
        # Fallback error handling
        try:
            messagebox.showerror("Application Error", f"An unexpected error occurred:\n{str(e)}")
        except:
            print(f"Fatal error: {e}")


if __name__ == '__main__':
    main()
