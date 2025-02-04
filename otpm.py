import asyncio
import mitmproxy
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
import threading
import time
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.by import By
import logging
import sys

class OTPInterceptor:
    def __init__(self):
        self.driver = None  # WebDriver instance

    def start_mitmproxy(self):
        """Starts mitmproxy inside a properly initialized asyncio event loop."""
        loop = asyncio.new_event_loop()  # Create a new asyncio event loop
        asyncio.set_event_loop(loop)  # Set it as the current event loop

        options = Options(listen_host='127.0.0.1', listen_port=8080)
        m = DumpMaster(options, with_termlog=False, with_dumper=False)

        try:
            loop.run_until_complete(m.run())  # Run mitmproxy in this loop
        except KeyboardInterrupt:
            m.shutdown()
        except Exception as e:
            logging.error(f"Mitmproxy Error: {e}")
            m.shutdown()

    def launch_firefox(self):
        """Launches Firefox configured with mitmproxy."""
        firefox_options = FirefoxOptions()
        firefox_options.add_argument("--proxy-server=127.0.0.1:8080")  # Set proxy
        firefox_options.add_argument("--headless")  # Run in headless mode

        self.driver = webdriver.Firefox(options=firefox_options)
        self.driver.get("http://example.com")  # Change to your target website

        try:
            time.sleep(5)  # Wait for the page to load
            logging.info("Firefox launched successfully!")
        except Exception as e:
            logging.error(f"Error launching Firefox: {e}")

    def close_browser(self):
        """Closes the browser if it's running."""
        if self.driver:
            self.driver.quit()
            logging.info("Browser closed.")

def start_mitmproxy_thread(interceptor):
    """Runs mitmproxy inside a properly initialized asyncio event loop."""
    interceptor.start_mitmproxy()

def launch_firefox_thread(interceptor):
    """Launches Firefox in a separate thread."""
    interceptor.launch_firefox()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    interceptor = OTPInterceptor()

    # Start mitmproxy in a separate thread
    mitmproxy_thread = threading.Thread(target=start_mitmproxy_thread, args=(interceptor,), daemon=True)
    mitmproxy_thread.start()

    # Start Firefox in a separate thread
    browser_thread = threading.Thread(target=launch_firefox_thread, args=(interceptor,), daemon=True)
    browser_thread.start()

    try:
        mitmproxy_thread.join()
        browser_thread.join()
    except KeyboardInterrupt:
        interceptor.close_browser()
        logging.info("Script terminated by user.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        interceptor.close_browser()
        sys.exit(1)
