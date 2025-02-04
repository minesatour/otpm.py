import asyncio
import mitmproxy
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options as ChromeOptions
from webdriver_manager.chrome import ChromeDriverManager
import time
import threading

class OTPInterceptor:
    def __init__(self):
        self.driver = None

    def start_mitmproxy(self):
        """Starts mitmproxy with a separate asyncio event loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Configure mitmproxy options
        options = Options(listen_host='127.0.0.1', listen_port=8080)
        m = DumpMaster(options, with_termlog=False, with_dumper=False)

        try:
            loop.run_until_complete(m.run())
        except KeyboardInterrupt:
            m.shutdown()

    def launch_chrome(self):
        """Launches a headless Chrome browser with mitmproxy interception."""
        chrome_options = ChromeOptions()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--proxy-server=http://127.0.0.1:8080")  # Route traffic through mitmproxy

        # Automatically fetch the correct ChromeDriver version
        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=chrome_options)

        try:
            self.driver.get("http://example.com")  # Replace with the real target URL
            time.sleep(10)  # Adjust based on OTP retrieval timing
        finally:
            self.driver.quit()

    def response(self, flow: mitmproxy.http.HTTPFlow):
        """Intercepts and logs OTP-related responses."""
        if "otp" in flow.request.pretty_url:
            print(f"Intercepted OTP response: {flow.response.content.decode('utf-8')}")

def start_mitmproxy_thread():
    """Thread function to start mitmproxy."""
    interceptor = OTPInterceptor()
    interceptor.start_mitmproxy()

def launch_chrome_thread():
    """Thread function to launch Chrome."""
    interceptor = OTPInterceptor()
    interceptor.launch_chrome()

if __name__ == "__main__":
    # Start mitmproxy in a separate thread
    mitmproxy_thread = threading.Thread(target=start_mitmproxy_thread, daemon=True)
    mitmproxy_thread.start()

    # Start the browser automation in a separate thread
    chrome_thread = threading.Thread(target=launch_chrome_thread, daemon=True)
    chrome_thread.start()

    # Join threads so the main program waits for them to finish
    mitmproxy_thread.join()
    chrome_thread.join()
