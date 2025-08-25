import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog, ttk
import hashlib
import json
import os
import base64
from cryptography.fernet import Fernet
from tkinter import Canvas
import time

# Define color scheme
COLORS = {
    'primary': '#1a237e',
    'secondary': '#3f51b5',
    'accent': '#ff4081',
    'text': '#ffffff',
    'background': '#f5f5f5',
    'card': '#ffffff',
    'shadow': '#333333',  # Changed from '#00000020' to a valid hex color
    'hover': '#5c6bc0'
}

# Database and User Management (unchanged)
class UserDatabase:
    def __init__(self, filename='users.json'):
        self.filename = filename
        self.users = {}
        self.load_users()
    
    def load_users(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                self.users = json.load(f)
    
    def save_users(self):
        with open(self.filename, 'w') as f:
            json.dump(self.users, f, indent=4)
    
    def add_user(self, username, password, email):
        if username in self.users:
            return False
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        self.users[username] = {
            'password': hashed_pw,
            'email': email,
            'failed_attempts': 0,
            'locked': False
        }
        self.save_users()
        return True
    
    def verify_user(self, username, password):
        if username not in self.users:
            return False
        
        user = self.users[username]
        if user['locked']:
            return False
        
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        if user['password'] == hashed_pw:
            user['failed_attempts'] = 0
            self.save_users()
            return True
        else:
            user['failed_attempts'] += 1
            if user['failed_attempts'] >= 5:
                user['locked'] = True
            self.save_users()
            return False

# File Encryption (unchanged)
class FileEncryptor:
    @staticmethod
    def _get_key(password):
        digest = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(digest[:32])

    @staticmethod
    def encrypt_file(filepath, password):
        try:
            key = FileEncryptor._get_key(password)
            cipher = Fernet(key)
            
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = cipher.encrypt(file_data)
            encrypted_path = filepath + '.enc'
            
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            os.remove(filepath)
            return encrypted_path
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    @staticmethod
    def decrypt_file(encrypted_path, password, output_path=None):
        try:
            key = FileEncryptor._get_key(password)
            cipher = Fernet(key)
            
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = cipher.decrypt(encrypted_data)
            output = output_path if output_path else encrypted_path[:-4]
            
            with open(output, 'wb') as f:
                f.write(decrypted_data)
            
            return output
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

# Enhanced UI Application
class SecuritySystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Security System")
        self.root.geometry("700x550")
        self.root.minsize(600, 450)
        self.root.configure(bg=COLORS['background'])
        
        self.db = UserDatabase()
        
        # Create default admin if not exists
        if 'admin' not in self.db.users:
            self.db.add_user('admin', 'admin123', 'admin@example.com')
        
        # Create gradient background
        self.canvas = Canvas(self.root, highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)
        self.create_gradient()
        
        # Configure ttk style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        self.container = None
        self.show_login_screen()
        
        # Bind window resize
        self.root.bind('<Configure>', self.on_resize)
    
    def create_gradient(self):
        width = self.root.winfo_screenwidth()
        height = self.root.winfo_screenheight()
        self.canvas.delete("all")
        for i in range(height):
            r = int(245 - (i * (245-26)/height))
            g = int(245 - (i * (245-35)/height))
            b = int(245 - (i * (245-126)/height))
            color = f'#{r:02x}{g:02x}{b:02x}'
            self.canvas.create_line(0, i, width, i, fill=color)
    
    def on_resize(self, event):
        self.create_gradient()
        if self.container:
            self.container.place(relx=0.5, rely=0.5, anchor='center')
    
    def configure_styles(self):
        # Button style
        self.style.configure('Custom.TButton',
                            background=COLORS['secondary'],
                            foreground=COLORS['text'],
                            font=('Arial', 12),
                            padding=10,
                            borderwidth=0)
        self.style.map('Custom.TButton',
                      background=[('active', COLORS['hover'])])
        
        # Entry style
        self.style.configure('Custom.TEntry',
                           fieldbackground='#ffffff',
                           foreground=COLORS['primary'],
                           font=('Arial', 12),
                           padding=8)
        
        # Label style
        self.style.configure('Custom.TLabel',
                           background=COLORS['card'],
                           foreground=COLORS['primary'],
                           font=('Arial', 14))
    
    def create_card_frame(self):
        frame = tk.Frame(self.canvas, bg=COLORS['card'])
        frame.configure(
            highlightbackground=COLORS['shadow'],
            highlightthickness=2,
            bd=0
        )
        # Add shadow effect
        frame.place(relx=0.5, rely=0.5, anchor='center')
        return frame
    
    def show_login_screen(self):
        self.clear_screen()
        
        self.container = self.create_card_frame()
        self.container.configure(padx=30, pady=30)
        
        # Title
        ttk.Label(
            self.container,
            text="🔒 Secure Login",
            style='Custom.TLabel',
            font=('Arial', 24, 'bold')
        ).pack(pady=(20, 30))
        
        # Form
        form_frame = tk.Frame(self.container, bg=COLORS['card'])
        form_frame.pack(fill='x')
        
        # Username
        ttk.Label(form_frame, text="Username:", style='Custom.TLabel').grid(row=0, column=0, padx=10, pady=10, sticky='e')
        self.username_entry = ttk.Entry(form_frame, style='Custom.TEntry')
        self.username_entry.grid(row=0, column=1, padx=10, pady=10, sticky='ew')
        
        # Password
        ttk.Label(form_frame, text="Password:", style='Custom.TLabel').grid(row=1, column=0, padx=10, pady=10, sticky='e')
        self.password_entry = ttk.Entry(form_frame, style='Custom.TEntry', show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10, sticky='ew')
        
        # Buttons
        button_frame = tk.Frame(self.container, bg=COLORS['card'])
        button_frame.pack(fill='x', pady=20)
        
        ttk.Button(
            button_frame,
            text="Login",
            style='Custom.TButton',
            command=self.login
        ).pack(fill='x', pady=5)
        
        ttk.Button(
            button_frame,
            text="Register",
            style='Custom.TButton',
            command=self.show_register
        ).pack(fill='x', pady=5)
        
        ttk.Button(
            button_frame,
            text="Forgot Password",
            style='Custom.TButton',
            command=self.show_reset
        ).pack(fill='x', pady=5)
        
        # Animation
        self.container.place(relx=0.5, rely=0.5, anchor='center')
        self.animate_fade_in(self.container)
    
    def show_register(self):
        self.clear_screen()
        
        self.container = self.create_card_frame()
        self.container.configure(padx=30, pady=30)
        
        ttk.Label(
            self.container,
            text="📝 Register New User",
            style='Custom.TLabel',
            font=('Arial', 24, 'bold')
        ).pack(pady=(20, 30))
        
        form_frame = tk.Frame(self.container, bg=COLORS['card'])
        form_frame.pack(fill='x')
        
        # Username
        ttk.Label(form_frame, text="Username:", style='Custom.TLabel').grid(row=0, column=0, padx=10, pady=10, sticky='e')
        username_entry = ttk.Entry(form_frame, style='Custom.TEntry')
        username_entry.grid(row=0, column=1, padx=10, pady=10, sticky='ew')
        
        # Password
        ttk.Label(form_frame, text="Password:", style='Custom.TLabel').grid(row=1, column=0, padx=10, pady=10, sticky='e')
        password_entry = ttk.Entry(form_frame, style='Custom.TEntry', show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=10, sticky='ew')
        
        # Email
        ttk.Label(form_frame, text="Email:", style='Custom.TLabel').grid(row=2, column=0, padx=10, pady=10, sticky='e')
        email_entry = ttk.Entry(form_frame, style='Custom.TEntry')
        email_entry.grid(row=2, column=1, padx=10, pady=10, sticky='ew')
        
        def register():
            username = username_entry.get()
            password = password_entry.get()
            email = email_entry.get()
            
            if not username or not password or not email:
                messagebox.showerror("Error", "All fields are required", parent=self.root)
                return
            
            if self.db.add_user(username, password, email):
                messagebox.showinfo("Success", "Registration successful!", parent=self.root)
                self.show_login_screen()
            else:
                messagebox.showerror("Error", "Username already exists", parent=self.root)
        
        button_frame = tk.Frame(self.container, bg=COLORS['card'])
        button_frame.pack(fill='x', pady=20)
        
        ttk.Button(button_frame, text="Register", style='Custom.TButton', command=register).pack(fill='x', pady=5)
        ttk.Button(button_frame, text="Back", style='Custom.TButton', command=self.show_login_screen).pack(fill='x', pady=5)
        
        self.animate_fade_in(self.container)
    
    def show_reset(self):
        self.clear_screen()
        
        self.container = self.create_card_frame()
        self.container.configure(padx=30, pady=30)
        
        ttk.Label(
            self.container,
            text="🔄 Password Reset",
            style='Custom.TLabel',
            font=('Arial', 24, 'bold')
        ).pack(pady=(20, 30))
        
        form_frame = tk.Frame(self.container, bg=COLORS['card'])
        form_frame.pack(fill='x')
        
        ttk.Label(form_frame, text="Username:", style='Custom.TLabel').grid(row=0, column=0, padx=10, pady=10, sticky='e')
        username_entry = ttk.Entry(form_frame, style='Custom.TEntry')
        username_entry.grid(row=0, column=1, padx=10, pady=10, sticky='ew')
        
        ttk.Label(form_frame, text="New Password:", style='Custom.TLabel').grid(row=1, column=0, padx=10, pady=10, sticky='e')
        new_pass_entry = ttk.Entry(form_frame, style='Custom.TEntry', show="*")
        new_pass_entry.grid(row=1, column=1, padx=10, pady=10, sticky='ew')
        
        def reset_password():
            username = username_entry.get()
            new_pass = new_pass_entry.get()
            
            if username not in self.db.users:
                messagebox.showerror("Error", "Username not found", parent=self.root)
                return
            
            hashed_pw = hashlib.sha256(new_pass.encode()).hexdigest()
            self.db.users[username]['password'] = hashed_pw
            self.db.users[username]['locked'] = False
            self.db.save_users()
            messagebox.showinfo("Success", "Password reset successful!", parent=self.root)
            self.show_login_screen()
        
        button_frame = tk.Frame(self.container, bg=COLORS['card'])
        button_frame.pack(fill='x', pady=20)
        
        ttk.Button(button_frame, text="Reset Password", style='Custom.TButton', command=reset_password).pack(fill='x', pady=5)
        ttk.Button(button_frame, text="Back", style='Custom.TButton', command=self.show_login_screen).pack(fill='x', pady=5)
        
        self.animate_fade_in(self.container)
    
    def show_dashboard(self, username):
        self.clear_screen()
        
        self.container = self.create_card_frame()
        self.container.configure(padx=30, pady=30)
        
        ttk.Label(
            self.container,
            text=f"👤 Welcome, {username}!",
            style='Custom.TLabel',
            font=('Arial', 24, 'bold')
        ).pack(pady=(20, 30))
        
        ttk.Label(
            self.container,
            text="🔐 File Encryption",
            style='Custom.TLabel',
            font=('Arial', 18, 'bold')
        ).pack(pady=20)
        
        button_frame = tk.Frame(self.container, bg=COLORS['card'])
        button_frame.pack(fill='x', pady=20)
        
        ttk.Button(
            button_frame,
            text="📤 Encrypt File",
            style='Custom.TButton',
            command=lambda: self.encrypt_file_ui(username)
        ).pack(fill='x', pady=5)
        
        ttk.Button(
            button_frame,
            text="📥 Decrypt File",
            style='Custom.TButton',
            command=lambda: self.decrypt_file_ui(username)
        ).pack(fill='x', pady=5)
        
        ttk.Button(
            button_frame,
            text="🚪 Logout",
            style='Custom.TButton',
            command=self.show_login_screen
        ).pack(fill='x', pady=20)
        
        self.animate_fade_in(self.container)
    
    def animate_fade_in(self, widget):
        alpha = 0.0
        def fade():
            nonlocal alpha
            alpha += 0.1
            # Use solid color instead of alpha for Tkinter compatibility
            widget.configure(bg=COLORS['card'])
            if alpha < 1.0:
                self.root.after(50, fade)
        fade()
    
    def encrypt_file_ui(self, username):
        filepath = filedialog.askopenfilename(parent=self.root)
        if not filepath:
            return
        
        password = simpledialog.askstring(
            "Password",
            "Enter your password:",
            show='*',
            parent=self.root
        )
        if not password or not self.db.verify_user(username, password):
            messagebox.showerror("Error", "Invalid password", parent=self.root)
            return
        
        # Show loading indicator
        loading = ttk.Label(self.container, text="Encrypting...", style='Custom.TLabel')
        loading.pack(pady=10)
        self.root.update()
        
        try:
            encrypted_path = FileEncryptor.encrypt_file(filepath, password)
            loading.destroy()
            messagebox.showinfo("Success", f"File encrypted as:\n{encrypted_path}", parent=self.root)
        except Exception as e:
            loading.destroy()
            messagebox.showerror("Error", str(e), parent=self.root)
    
    def decrypt_file_ui(self, username):
        filepath = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")], parent=self.root)
        if not filepath:
            return
        
        password = simpledialog.askstring(
            "Password",
            "Enter your password:",
            show='*',
            parent=self.root
        )
        if not password or not self.db.verify_user(username, password):
            messagebox.showerror("Error", "Invalid password", parent=self.root)
            return
        
        # Show loading indicator
        loading = ttk.Label(self.container, text="Decrypting...", style='Custom.TLabel')
        loading.pack(pady=10)
        self.root.update()
        
        try:
            output_path = filedialog.asksaveasfilename(defaultextension=".*", parent=self.root)
            if output_path:
                FileEncryptor.decrypt_file(filepath, password, output_path)
                loading.destroy()
                messagebox.showinfo("Success", f"File decrypted to:\n{output_path}", parent=self.root)
        except Exception as e:
            loading.destroy()
            messagebox.showerror("Error", str(e), parent=self.root)
    
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password", parent=self.root)
            return
        
        # Show loading indicator
        loading = ttk.Label(self.container, text="Logging in...", style='Custom.TLabel')
        loading.pack(pady=10)
        self.root.update()
        
        if self.db.verify_user(username, password):
            loading.destroy()
            self.show_dashboard(username)
        else:
            loading.destroy()
            messagebox.showerror("Error", "Invalid credentials or account locked", parent=self.root)
    
    def clear_screen(self):
        if self.container:
            self.container.destroy()
        for widget in self.canvas.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecuritySystem(root)
    root.mainloop()