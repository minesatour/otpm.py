import asyncio
import mitmproxy
from mitmproxy.tools.dump import DumpMaster
import tkinter as tk
from tkinter import messagebox
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time

# Function to launch Chrome with Selenium
def launch_chrome():
    # Set up Chrome options
    chrome_options = Options()
    chrome_options.add_argument("--proxy-server=http://127.0.0.1:8080")  # Set mitmproxy as the proxy

    # Specify the actual path to the chromedriver executable
    chromedriver_path = '/usr/local/bin/chromedriver'

    # Create a new Chrome browser instance with Selenium
    driver = webdriver.Chrome(executable_path=chromedriver_path, options=chrome_options)

    # Open a URL (e.g., user input or pre-defined URL)
    driver.get("https://example.com")  # Modify this to the desired website

    # Wait for user to interact or for OTP to be triggered
    time.sleep(30)  # Adjust sleep time to match interaction time
    # The script will continue to monitor OTP capture during this time

    return driver


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

# Function to intercept HTTP requests and responses
class OTPInterceptor:
    def __init__(self):
        self.gui = None

    def set_gui(self, gui):
        self.gui = gui

    def response(self, flow: mitmproxy.http.HTTPFlow):
        # Look for OTPs in the response body (e.g., in the HTML or JSON response)
        if flow.response.content:
            content = flow.response.content.decode('utf-8', errors='ignore')
            otp_matches = re.findall(otp_pattern, content)
            if otp_matches:
                otp = otp_matches[0]  # Taking the first match (adjust as necessary)
                if self.gui:
                    self.gui.update_otp(otp)
                    ctx.log.info(f"Captured OTP: {otp}")

# Set up the mitmproxy add-on
def start_mitmproxy():
    # Initialize the GUI
    root = tk.Tk()
    gui = OTPGUI(root)

    # Create the interceptor and link the GUI
    interceptor = OTPInterceptor()
    interceptor.set_gui(gui)

    # Run mitmproxy with the interceptor
    options = mitmproxy.options.Options(listen_host='127.0.0.1', listen_port=8080)
    m = DumpMaster(options)

    # Add the interceptor to the mitmproxy master
    m.addons.add(interceptor)

    # Use asyncio.run to run the event loop for mitmproxy
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(m.run())

    # Launch Chrome and start monitoring OTP
    launch_chrome()

    # Start the tkinter main loop
    root.mainloop()

if __name__ == "__main__":
    start_mitmproxy()
