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
import logging
import os
import yaml  # For configuration management

# CONFIGURATIONS
CONFIG_FILE = "config.yaml"
OTP_STORAGE_FILE = "captured_otps.db"
OTP_PATTERN = r"\b\d{6}\b"  # Adjust this pattern based on the OTP format
ALLOWED_SITES_FILE = "allowed_sites.txt"

# User-Agent list for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; Pixel 3 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    # Add more User-Agents as needed
]

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration from YAML file
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as file:
            return yaml.safe_load(file)
    else:
        logging.warning("Configuration file not found. Using default settings.")
        return {}

# SETUP DATABASE
def setup_database():
    try:
        conn = sqlite3.connect(OTP_STORAGE_FILE)
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS otps (id INTEGER PRIMARY KEY, otp TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
        conn.commit()
        conn.close()
        logging.info("Database setup complete.")
    except Exception as e:
        logging.error(f"Error setting up database: {e}")

# STORE OTP IN DATABASE
def store_otp(otp):
    try:
        conn = sqlite3.connect(OTP_STORAGE_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO otps (otp) VALUES (?)", (otp,))
        conn.commit()
        conn.close()
        logging.info(f"Stored OTP: {otp}")
    except Exception as e:
        logging.error(f"Error storing OTP: {e}")

# GUI TO DISPLAY OTP
class OTPGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Captured OTP")
        self.master.geometry("300x200")
        self.otp_label = tk.Label(master, text="Waiting for OTP...", font=("Arial", 12))
        self.otp_label.pack(pady=20)

        self.capture_button = tk.Button(master, text="Capture OTP", command=self.start_capturing)
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
    user_agent = random.choice(USER_AGENTS)
    chrome_options.add_argument(f"user-agent={user_agent}")
    
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--start-maximized")  # Start maximized to see the browser

    try:
        driver = webdriver.Chrome(service=Service(CHROMEDRIVER_PATH), options=chrome_options)
        stealth(driver, languages=["en-US", "en"], vendor="Google Inc.", platform="Win32", webgl_vendor="Intel Inc.", renderer="Intel Iris OpenGL Engine", fix_hairline=True)
        driver.get(target_url)
        logging.info(f"Launched Chrome and navigated to {target_url}")
        return driver
    except Exception as e:
        logging.error(f"Error launching Chrome: {e}")
        return None

# Load allowed sites from a file
def load_allowed_sites():
    try:
        with open(ALLOWED_SITES_FILE, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        logging.error("Allowed sites file not found. Please create 'allowed_sites.txt'.")
        return []

# OTP INTERCEPTION
def intercept_otp(driver, gui, allowed_sites):
    while True:
        time.sleep(random.uniform(2, 5))  # Random delay between checks
        if gui.capturing:  # Only capture OTP if the user has clicked the button
            current_url = driver.current_url
            if any(site in current_url for site in allowed_sites):
                page_source = driver.page_source
                otp_matches = re.findall(OTP_PATTERN, page_source)
                if otp_matches:
                    otp = otp_matches[0]
                    gui.update_otp(otp)
                    logging.info(f"✅ Captured OTP: {otp}")

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
    menu()
    
    root = tk.Tk()
    gui = OTPGUI(root)
    
    allowed_sites = load_allowed_sites()
    if not allowed_sites:
        messagebox.showerror("Error", "No allowed sites found. Please add sites to 'allowed_sites.txt'.")
        return
    
    target_url = simpledialog.askstring("Target Website", "Enter the OTP website URL:")
    if target_url not in allowed_sites:
        messagebox.showerror("Error", "The entered URL is not in the
