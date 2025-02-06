import json
import re
import sqlite3
import threading
import time
import random
import tkinter as tk
from tkinter import messagebox, simpledialog
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium_stealth import stealth

# CONFIGURATIONS
CHROMEDRIVER_PATH = "/usr/bin/chromedriver"
OTP_STORAGE_FILE = "captured_otps.db"
ALLOWED_SITES_FILE = "allowed_sites.txt"
OTP_EXPIRY_HOURS = 24  # Purge OTPs older than this value

# OTP Detection Patterns
OTP_PATTERN = r"\b\d{6}\b"  # Adjust this pattern based on OTP format
OTP_KEYWORDS = [
    "Your OTP is", "Enter this code", "Verification code",
    "Security code", "2FA code", "One-time password",
    "Login code", "Confirm your identity", "Authenticate with this code"
]

# User-Agent list for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; Pixel 3 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

# SETUP DATABASE
def setup_database():
    conn = sqlite3.connect(OTP_STORAGE_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY, 
            otp TEXT, 
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# STORE OTP IN DATABASE
def store_otp(otp):
    conn = sqlite3.connect(OTP_STORAGE_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO otps (otp) VALUES (?)", (otp,))
    conn.commit()
    conn.close()

# CLEANUP OLD OTPs
def cleanup_otps():
    conn = sqlite3.connect(OTP_STORAGE_FILE)
    c = conn.cursor()
    c.execute(f"DELETE FROM otps WHERE timestamp < datetime('now', '-{OTP_EXPIRY_HOURS} hours')")
    conn.commit()
    conn.close()

# GUI TO DISPLAY OTP
class OTPGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Captured OTP")
        self.master.geometry("300x200")
        self.otp_label = tk.Label(master, text="Waiting for OTP...", font=("Arial", 12))
        self.otp_label.pack(pady=20)

        self.capture_button = tk.Button(master, text="Start OTP Capture", command=self.start_capturing)
        self.capture_button.pack(pady=10)

        self.capturing = False  # Flag to control OTP capturing

    def start_capturing(self):
        self.capturing = True
        self.otp_label.config(text="Capturing OTP...")

    def update_otp(self, otp):
        store_otp(otp)
        self.otp_label.config(text=f"Captured OTP: {otp}")
        messagebox.showinfo("OTP Captured", f"OTP: {otp}")

# CHROME DRIVER SETUP
def launch_chrome(target_url):
    chrome_options = ChromeOptions()
    chrome_options.add_argument(f"user-agent={random.choice(USER_AGENTS)}")
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--start-maximized")

    driver = webdriver.Chrome(service=Service(CHROMEDRIVER_PATH), options=chrome_options)
    stealth(driver, languages=["en-US", "en"], vendor="Google Inc.", platform="Win32",
            webgl_vendor="Intel Inc.", renderer="Intel Iris OpenGL Engine", fix_hairline=True)
    driver.get(target_url)
    return driver

# LOAD ALLOWED SITES
def load_allowed_sites():
    try:
        with open(ALLOWED_SITES_FILE, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print("Allowed sites file not found. Please create 'allowed_sites.txt'.")
        return []

# OTP INTERCEPTION (SMART DETECTION)
def intercept_otp(driver, gui, allowed_sites):
    otp_captured = False
    while True:
        time.sleep(random.uniform(2, 5))  # Randomised delay
        if gui.capturing:  # Only capture OTP if user activated capturing
            current_url = driver.current_url
            if any(site in current_url for site in allowed_sites):
                page_source = driver.page_source
                otp_candidates = re.findall(OTP_PATTERN, page_source)

                for otp in otp_candidates:
                    # Check for OTP keywords in surrounding text
                    if any(keyword in page_source for keyword in OTP_KEYWORDS):
                        if not otp_captured:  # Ensure only one OTP is captured
                            otp_captured = True
                            gui.update_otp(otp)
                            print(f"✅ Captured OTP: {otp}")
                            return  # Exit after capturing one OTP

# STARTUP MENU
def menu():
    print("1. Run with Proxy")
    print("2. Run without Proxy")
    choice = input("Choose an option: ")
    if choice == "1":
        print("Proxy option is not implemented in this version.")
    elif choice == "2":
        print("Running without proxy.")
    else:
        print("❌ Invalid choice. Defaulting to no proxy.")

# MAIN FUNCTION
def main():
    setup_database()
    cleanup_otps()  # Clean old OTPs on startup
    menu()
    
    root = tk.Tk()
    gui = OTPGUI(root)
    
    allowed_sites = load_allowed_sites()
    if not allowed_sites:
        messagebox.showerror("Error", "No allowed sites found. Please add sites to 'allowed_sites.txt'.")
        return
    
    target_url = simpledialog.askstring("Target Website", "Enter the OTP website URL:")
    if target_url not in allowed_sites:
        messagebox.showerror("Error", "The entered URL is not in the allowed sites list.")
        return
    
    messagebox.showinfo("Action Required", "🚀 Please log in and request the OTP.")
    
    driver = launch_chrome(target_url)
    
    # Run OTP interception in a separate thread
    intercept_thread = threading.Thread(target=intercept_otp, args=(driver, gui, allowed_sites))
    intercept_thread.daemon = True
    intercept_thread.start()
    
    root.mainloop()
    driver.quit()

if __name__ == "__main__":
    main()
