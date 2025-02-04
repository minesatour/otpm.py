import asyncio
import mitmproxy.http
from mitmproxy import ctx
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

import tkinter as tk
from tkinter import messagebox
import re
import threading
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service

# Regular expression pattern to capture OTP-like codes (e.g., 6-digit numbers)
otp_pattern = r"\b\d{6}\b"  # Simple pattern for 6-digit OTPs (you can refine this)

# Create a simple tkinter window for displaying OTP
class OTPGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Captured OTP")
        self.master.geometry("300x150")

        self.otp_label = tk.Label(master, text="OTP will appear here", font=("Arial", 12))
        self.otp_label.pack(pady=20)

    def update_otp(self, otp):
        self.otp_label.config(text=f"Captured OTP: {otp}")
        messagebox.showinfo("OTP Captured", f"OTP: {otp}")

# Function to intercept HTTP responses
class OTPInterceptor:
    def __init__(self):
        self.gui = None

    def set_gui(self, gui):
        self.gui = gui

    def response(self, flow: mitmproxy.http.HTTPFlow):
        if flow.response.content:
            content = flow.response.content.decode('utf-8', errors='ignore')
            otp_matches = re.findall(otp_pattern, content)
            if otp_matches:
                otp = otp_matches[0]  # Take the first match
                if self.gui:
                    self.gui.update_otp(otp)
                    ctx.log.info(f"Captured OTP: {otp}")

# Function to launch Chrome with Selenium
def launch_chrome():
    chrome_options = ChromeOptions()
    chrome_options.add_argument("--proxy-server=http://127.0.0.1:8080")  # Use mitmproxy as the proxy
    chrome_options.add_argument("--ignore-certificate-errors")  # Avoid SSL issues

    # Update the path to chromedriver if necessary
    chromedriver_path = "/usr/local/bin/chromedriver"  # Replace with the actual path to chromedriver

    # Create a new Chrome browser instance with Selenium
    driver = webdriver.Chrome(service=Service(chromedriver_path), options=chrome_options)

    # Open a URL (Modify this to the target website)
    driver.get("https://example.com")

    # Wait for the user to trigger an OTP
    time.sleep(30)  # Adjust sleep time based on interaction needs

    return driver

# Function to start mitmproxy
async def start_mitmproxy(gui):
    options = Options(listen_host='127.0.0.1', listen_port=8080)
    m = DumpMaster(options)

    # Create and add OTP interceptor
    interceptor = OTPInterceptor()
    interceptor.set_gui(gui)
    m.addons.add(interceptor)

    # Run mitmproxy
    await m.run()

# Main function to run mitmproxy, launch Chrome, and start the GUI
def main():
    # Initialize Tkinter GUI
    root = tk.Tk()
    gui = OTPGUI(root)

    # Start mitmproxy in a separate thread
    mitm_thread = threading.Thread(target=lambda: asyncio.run(start_mitmproxy(gui)))
    mitm_thread.start()

    # Launch Chrome in a separate thread
    chrome_thread = threading.Thread(target=launch_chrome)
    chrome_thread.start()

    # Start the Tkinter event loop
    root.mainloop()

if __name__ == "__main__":
    main()
