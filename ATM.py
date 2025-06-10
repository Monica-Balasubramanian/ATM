import streamlit as st
import sqlite3
import hashlib
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from PIL import Image
import os

# --- Helper Functions ---

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_users_table():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT,
        pin TEXT,
        balance INTEGER,
        email TEXT
    )
    ''')
    conn.commit()
    conn.close()

def create_transaction_table():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        amount INTEGER,
        balance_after INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    conn.commit()
    conn.close()

def add_user(username, password, pin, email):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password, pin, balance, email) VALUES (?, ?, ?, ?, ?)",
              (username, hash_password(password), pin, 1000, email))
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    return user

def update_balance(username, new_balance):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET balance=? WHERE username=?", (new_balance, username))
    conn.commit()
    conn.close()

def update_pin(username, new_pin):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET pin=? WHERE username=?", (new_pin, username))
    conn.commit()
    conn.close()

def add_transaction(username, action, amount, balance):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("INSERT INTO transactions (username, action, amount, balance_after) VALUES (?, ?, ?, ?)",
              (username, action, amount, balance))
    conn.commit()
    conn.close()

def get_transactions(username):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT timestamp, action, amount, balance_after FROM transactions WHERE username=? ORDER BY timestamp DESC", (username,))
    rows = c.fetchall()
    conn.close()
    return rows

# Email OTP sending function
def send_otp_email(receiver_email, otp_code):
    sender_email = st.secrets["EMAIL"]
    sender_password = st.secrets["EMAIL_PASSWORD"]


    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "Your ATM Withdrawal OTP Code"
    body = f"Your OTP to withdraw is: {otp_code}"
    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        return True
    except Exception as e:
        st.error(f"Failed to send OTP email: {e}")
        return False

# --- Initialize DB Tables ---
create_users_table()
create_transaction_table()

# --- Streamlit UI ---

st.title("🏦 ATM ")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "otp" not in st.session_state:
    st.session_state.otp = None
if "otp_validated" not in st.session_state:
    st.session_state.otp_validated = False

# --- Registration ---
def register():
    st.header("Create a new account")
    new_user = st.text_input("Username")
    new_email = st.text_input("Email")
    new_pin = st.text_input("4-digit PIN", max_chars=4, type="password")
    new_pass = st.text_input("Password", type="password")
    uploaded_file = st.file_uploader("Upload Profile Photo (png/jpg)", type=["png", "jpg"])
    
    if st.button("Register"):
        if not new_user or not new_pass or not new_pin or not new_email:
            st.error("Please fill all fields")
            return
        if len(new_pin) != 4 or not new_pin.isdigit():
            st.error("PIN must be exactly 4 digits")
            return
        if get_user(new_user):
            st.error("Username already exists")
            return
        add_user(new_user, new_pass, new_pin, new_email)
        if uploaded_file:
            with open(f"{new_user}.png", "wb") as f:
                f.write(uploaded_file.getbuffer())
        st.success("Registration successful! You can now log in.")

# --- Login ---
def login():
    st.header("Login to your account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user = get_user(username)
        if user and hash_password(password) == user[1]:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success(f"Welcome back, {username}!")
        else:
            st.error("Invalid username or password")

# --- Logout ---
def logout():
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.otp = None
    st.session_state.otp_validated = False
    st.success("Logged out successfully")

# --- Main ATM Dashboard ---
def atm_dashboard():
    user = get_user(st.session_state.username)
    balance = user[3]
    email = user[4]

    # Display profile photo
    try:
        img = Image.open(f"{st.session_state.username}.png")
        st.image(img, width=150, caption="Your Profile Photo")
    except:
        st.info("No profile photo found. Upload one during registration.")

    st.subheader(f"Balance: ₹{balance}")

    action = st.selectbox("Choose action:", ["Deposit", "Withdraw", "View Transactions", "Change PIN", "Logout"])

    if action == "Deposit":
        amount = st.number_input("Enter amount to deposit", min_value=1, step=1)
        if st.button("Deposit"):
            new_balance = balance + amount
            update_balance(st.session_state.username, new_balance)
            add_transaction(st.session_state.username, "Deposit", amount, new_balance)
            st.success(f"Deposited ₹{amount}. New balance: ₹{new_balance}")

    elif action == "Withdraw":
        amount = st.number_input("Enter amount to withdraw", min_value=1, step=1)
        if st.button("Withdraw"):
            if amount > balance:
                st.error("Insufficient balance.")
                return

            # OTP for withdrawal > 1000
            if amount > 1000:
                if st.session_state.otp is None:
                    st.session_state.otp = random.randint(100000, 999999)
                    sent = send_otp_email(email, st.session_state.otp)
                    if sent:
                        st.info("OTP sent to your email. Please enter it below.")
                    else:
                        st.error("Failed to send OTP email. Try again later.")
                        st.session_state.otp = None
                        return
                    st.session_state.otp_validated = False

                user_otp = st.text_input("Enter OTP", type="password")
                if st.button("Validate OTP"):
                    if user_otp == str(st.session_state.otp):
                        st.session_state.otp_validated = True
                        st.success("OTP validated successfully!")
                    else:
                        st.error("Invalid OTP. Please try again.")
                        return

                if not st.session_state.otp_validated:
                    st.warning("Please validate OTP before withdrawing.")
                    return

            # Proceed with withdrawal
            new_balance = balance - amount
            update_balance(st.session_state.username, new_balance)
            add_transaction(st.session_state.username, "Withdraw", amount, new_balance)
            st.success(f"Withdrew ₹{amount}. New balance: ₹{new_balance}")
            # Reset OTP after success
            st.session_state.otp = None
            st.session_state.otp_validated = False

    elif action == "View Transactions":
        st.subheader("Transaction History")
        transactions = get_transactions(st.session_state.username)
        if transactions:
            for tx in transactions:
                st.write(f"{tx[0]} | {tx[1]} | Amount: ₹{tx[2]} | Balance after: ₹{tx[3]}")
        else:
            st.info("No transactions found.")

    elif action == "Change PIN":
        new_pin = st.text_input("Enter new 4-digit PIN", max_chars=4, type="password")
        if st.button("Change PIN"):
            if len(new_pin) == 4 and new_pin.isdigit():
                update_pin(st.session_state.username, new_pin)
                st.success("PIN changed successfully.")
            else:
                st.error("PIN must be exactly 4 digits.")

    elif action == "Logout":
        logout()


# --- App flow ---
if not st.session_state.logged_in:

    if 'page' not in st.session_state:
        st.session_state.page = "Login"

    # Show the selected page form first
    if st.session_state.page == "Login":
        login()
        # Show only Register button below
        if st.button("Go to Register"):
            st.session_state.page = "Register"

    elif st.session_state.page == "Register":
        register()
        # Show only Login button below
        if st.button("Login"):
            st.session_state.page = "Login"

else:
    atm_dashboard()
