import streamlit as st
from scanner import scan_xss, scan_sql_injection
from admin_finder import find_admin_pages
import sqlite3
import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
import os
from datetime import datetime

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL,
                 email TEXT UNIQUE NOT NULL,
                 password TEXT NOT NULL,
                 token TEXT,
                 token_expiry TEXT,
                 created_at TEXT DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 url TEXT NOT NULL,
                 scan_type TEXT NOT NULL,
                 results TEXT,
                 timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

init_db()

# Email configuration (you should replace these with your actual SMTP settings)
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USERNAME = "your_email@example.com"
SMTP_PASSWORD = "your_password"
SENDER_EMAIL = "noreply@securescan.com"

# Utility functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token():
    return secrets.token_urlsafe(32)

def send_reset_email(email, token):
    reset_link = f"http://localhost:8501/reset_password?token={token}"
    message = f"""Click the link to reset your password:
{reset_link}

This link will expire in 1 hour."""
    
    msg = MIMEText(message)
    msg['Subject'] = 'SecureScan Pro - Password Reset'
    msg['From'] = SENDER_EMAIL
    msg['To'] = email
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        st.error(f"Failed to send email: {str(e)}")
        return False

# Authentication functions
def register_user(name, email, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    hashed_pw = hash_password(password)
    try:
        c.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                  (name, email, hashed_pw))
        conn.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, "Email already exists"
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()

def verify_user(email, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    hashed_pw = hash_password(password)
    c.execute("SELECT id, name, email FROM users WHERE email=? AND password=?", (email, hashed_pw))
    user = c.fetchone()
    conn.close()
    return user if user else None

def get_user_by_email(email):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, name, email FROM users WHERE email=?", (email,))
    user = c.fetchone()
    conn.close()
    return user if user else None

def create_reset_token(email):
    token = generate_token()
    expiry = datetime.now().timestamp() + 3600  # 1 hour from now
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET token=?, token_expiry=? WHERE email=?", 
              (token, expiry, email))
    conn.commit()
    conn.close()
    return token

def verify_reset_token(token):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT email FROM users WHERE token=? AND token_expiry > ?", 
              (token, datetime.now().timestamp()))
    user = c.fetchone()
    conn.close()
    return user[0] if user else None

def update_password(email, new_password):
    hashed_pw = hash_password(new_password)
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET password=?, token=NULL, token_expiry=NULL WHERE email=?", 
              (hashed_pw, email))
    conn.commit()
    conn.close()

def add_scan_history(user_id, url, scan_type, results):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO scan_history (user_id, url, scan_type, results) VALUES (?, ?, ?, ?)",
              (user_id, url, scan_type, results))
    conn.commit()
    conn.close()

def get_scan_history(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT url, scan_type, timestamp FROM scan_history WHERE user_id=? ORDER BY timestamp DESC LIMIT 10", (user_id,))
    history = c.fetchall()
    conn.close()
    return history

# UI Components
def login_page():
    st.title("SecureScan Pro Login")
    
    with st.form("login_form"):
        email = st.text_input("Email", placeholder="your@email.com")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            if not email or not password:
                st.error("Please fill in all fields")
            else:
                user = verify_user(email, password)
                if user:
                    st.session_state.user = {
                        "id": user[0],
                        "name": user[1],
                        "email": user[2]
                    }
                    st.session_state.page = "main"
                    st.rerun()
                else:
                    # Check what exactly is wrong
                    existing_user = get_user_by_email(email)
                    if existing_user:
                        st.error("Incorrect password")
                        st.markdown("[Forgot Password?](#forgot_password)")
                    else:
                        st.error("User not found! Please register.")
                        st.markdown("[Register Now](#register)")

    st.markdown("""
    <style>
    a {
        text-decoration: none;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown("Don't have an account? [Register Here](#register)")

def register_page():
    st.title("Register for SecureScan Pro")
    
    with st.form("register_form"):
        name = st.text_input("Full Name", placeholder="John Doe")
        email = st.text_input("Email", placeholder="your@email.com")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register")
        
        if submitted:
            if not all([name, email, password, confirm_password]):
                st.error("Please fill in all fields")
            elif password != confirm_password:
                st.error("Passwords don't match")
            else:
                success, message = register_user(name, email, password)
                if success:
                    st.success("Registration successful! Please login.")
                    st.session_state.page = "login"
                    st.rerun()
                else:
                    st.error(f"Registration failed: {message}")

    st.markdown("Already have an account? [Login Here](#login)")

def forgot_password_page():
    st.title("Password Recovery")
    
    with st.form("forgot_password_form"):
        email = st.text_input("Enter your email", placeholder="your@email.com")
        submitted = st.form_submit_button("Send Reset Link")
        
        if submitted:
            if not email:
                st.error("Please enter your email")
            else:
                user = get_user_by_email(email)
                if user:
                    token = create_reset_token(email)
                    if send_reset_email(email, token):
                        st.success("Password reset link has been sent to your email")
                    else:
                        st.error("Failed to send reset email. Please try again later.")
                else:
                    st.error("Email not found. Please register.")
                    st.markdown("[Register Now](#register)")

    st.markdown("[Back to Login](#login)")

def reset_password_page(token):
    st.title("Reset Password")
    
    email = verify_reset_token(token)
    if not email:
        st.error("Invalid or expired reset token")
        st.markdown("[Request new reset link](#forgot_password)")
        return
    
    with st.form("reset_password_form"):
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm New Password", type="password")
        submitted = st.form_submit_button("Reset Password")
        
        if submitted:
            if not new_password or not confirm_password:
                st.error("Please fill in all fields")
            elif new_password != confirm_password:
                st.error("Passwords don't match")
            else:
                update_password(email, new_password)
                st.success("Password updated successfully! Please login.")
                st.session_state.page = "login"
                st.rerun()

def main_page():
    # Sidebar with user profile and settings
    with st.sidebar:
        st.title("Settings")
        
        # Theme toggle
        theme = st.selectbox("Theme", ["Light", "Dark"], index=0)
        if theme == "Dark":
            st.session_state.theme = "dark"
        else:
            st.session_state.theme = "light"
        
        st.divider()
        
        # User profile section
        st.subheader("User Profile")
        if 'user' in st.session_state:
            st.write(f"**Name:** {st.session_state.user['name']}")
            st.write(f"**Email:** {st.session_state.user['email']}")
            
            # Scan history
            st.divider()
            st.subheader("Recent Scans")
            history = get_scan_history(st.session_state.user['id'])
            if history:
                for scan in history:
                    st.caption(f"{scan[2]}: {scan[0]} ({scan[1]})")
            else:
                st.caption("No scan history yet")
            
            st.divider()
            
            # Logout and delete account
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Logout"):
                    del st.session_state.user
                    st.session_state.page = "login"
                    st.rerun()
            with col2:
                if st.button("Delete Account", type="secondary"):
                    st.session_state.show_delete_confirmation = True
            
            if st.session_state.get('show_delete_confirmation', False):
                st.warning("Are you sure you want to delete your account? This cannot be undone.")
                if st.button("Confirm Delete"):
                    conn = sqlite3.connect('users.db')
                    c = conn.cursor()
                    c.execute("DELETE FROM users WHERE id=?", (st.session_state.user['id'],))
                    c.execute("DELETE FROM scan_history WHERE user_id=?", (st.session_state.user['id'],))
                    conn.commit()
                    conn.close()
                    del st.session_state.user
                    st.session_state.page = "login"
                    st.rerun()
                if st.button("Cancel"):
                    st.session_state.show_delete_confirmation = False
                    st.rerun()
    
    # Main content
    st.title("SecureScan Pro")
    st.caption("Professional Web Security Assessment Tool")
    
    # Add logo if exists
    if os.path.exists("assets/logo.png"):
        st.image("assets/logo.png", width=100)
    
    # Legal Disclaimer - MUST BE VISIBLE
    st.warning("""
    ## LEGAL DISCLAIMER
    This tool is for EDUCATIONAL PURPOSES ONLY. Use only on websites you own or have explicit permission to scan.
    Unauthorized scanning is ILLEGAL and may result in criminal charges. By using this tool, you accept all liability.
    """)
    
    # Scan Controls
    url = st.text_input("🔗 Enter target URL (e.g., https://example.com)", placeholder="https://")
    
    # Terms agreement checkbox
    agree = st.checkbox("I confirm I have permission to scan this website")
    scan_button = st.button("Scan Now", disabled=not agree)
    
    if scan_button:
        if not url.startswith(('http://', 'https://')):
            st.error("❌ Invalid URL - must start with http:// or https://")
        else:
            # Scanning process
            with st.spinner("🔍 Initializing security scan..."):
                tab1, tab2, tab3 = st.tabs(["XSS Scan", "SQLi Scan", "Admin Pages"])
                
                with tab1:
                    with st.spinner("Scanning for XSS vulnerabilities..."):
                        xss_found, xss_result = scan_xss(url)
                        st.info(xss_result)
                        add_scan_history(st.session_state.user['id'], url, "XSS Scan", xss_result)
                
                with tab2:
                    with st.spinner("Scanning for SQL Injection..."):
                        sqli_found, sqli_result = scan_sql_injection(url)
                        st.info(sqli_result)
                        add_scan_history(st.session_state.user['id'], url, "SQLi Scan", sqli_result)
                
                with tab3:
                    with st.spinner("Checking for admin interfaces..."):
                        admin_pages = find_admin_pages(url)
                        if admin_pages:
                            st.warning("⚠ Admin pages found:")
                            for page in admin_pages:
                                st.write(f"- {page}")
                            add_scan_history(st.session_state.user['id'], url, "Admin Page Finder", "\n".join(admin_pages))
                        else:
                            st.success("✅ No common admin pages detected")
                            add_scan_history(st.session_state.user['id'], url, "Admin Page Finder", "No admin pages found")

            # Summary
            st.divider()
            if xss_found or sqli_found or admin_pages:
                st.error("## ⚠ Vulnerabilities Found!")
                if xss_found:
                    st.error("- XSS vulnerabilities detected")
                if sqli_found:
                    st.error("- SQL injection vulnerabilities detected")
                if admin_pages:
                    st.error("- Admin interfaces exposed")
            else:
                st.success("## ✅ No obvious vulnerabilities detected")
            
            st.info("""
            Note: This is a basic scan only. A clean result doesn't guarantee security.
            Consider professional penetration testing for comprehensive assessment.
            """)

# Main app flow
def main():
    # Initialize session state
    if 'page' not in st.session_state:
        st.session_state.page = "login"
    
    # Page routing
    if st.session_state.page == "login":
        login_page()
    elif st.session_state.page == "register":
        register_page()
    elif st.session_state.page == "forgot_password":
        forgot_password_page()
    elif st.session_state.page == "reset_password":
        if 'token' in st.query_params:
            reset_password_page(st.query_params['token'])
        else:
            st.error("Invalid reset link")
            st.markdown("[Go to login](#login)")
    elif st.session_state.page == "main":
        if 'user' in st.session_state:
            main_page()
        else:
            st.session_state.page = "login"
            st.rerun()

if __name__ == "__main__":
    main()
