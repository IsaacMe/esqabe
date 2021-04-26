# ---------------------------------------------------------------
# Encrypted Search Query Analysis By Eavesdropping (ESQABE)
# Copyright (C) 2021  Isaac Meers (Hasselt University/EDM)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Please cite the paper if you are using this source code.
# ---------------------------------------------------------------

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
import subprocess
import os
from slugify import slugify
from .web_driver_utils import delete_cache_chrome
import time

BROWSER_CAPTURE_COUNT = 3
FILE_EXT = '.pcapng'
BLANK_PAGE = 'about:blank'
RUN_HEADLESS = True


class FingerprintVisitor:
    def __init__(self) -> None:
        super().__init__()

        self.chrome_driver = self.setup_new_chrome()
        self.firefox_driver = self.setup_new_ff()

        self.active_capture = None

    def __del__(self):
        self.chrome_driver.quit()
        self.firefox_driver.quit()

    def setup_new_chrome(self):
        chrome_options = ChromeOptions()
        chrome_options.headless = RUN_HEADLESS
        return webdriver.Chrome(options=chrome_options)

    def restart_chrome(self):
        self.chrome_driver = self.setup_new_chrome()
        return self.chrome_driver

    def restart_firefox(self):
        self.firefox_driver = self.setup_new_ff()
        return self.firefox_driver

    def setup_new_ff(self):
        profile = webdriver.FirefoxProfile()
        profile.set_preference("browser.cache.disk.enable", False)
        profile.set_preference("browser.cache.memory.enable", False)
        profile.set_preference("browser.cache.offline.enable", False)
        profile.set_preference("network.http.use-cache", False)
        profile.set_preference("browser.cache.disk.smart_size.enabled", False)
        profile.set_preference("browser.cache.disk_cache_ssl", False)

        firefox_options = FirefoxOptions()
        firefox_options.headless = RUN_HEADLESS
        return webdriver.Firefox(options=firefox_options, firefox_profile=profile)

    def generate_fingerprint(self, url, capture_folder, name=None):
        self.chrome_driver.delete_all_cookies()
        self.firefox_driver.delete_all_cookies()
        capture_files = []

        if name is None:
            name = url
        name = slugify(name)

        for driver in ['ff', 'chrome']:
            if driver == 'chrome':
                current_driver = self.chrome_driver
            else:
                current_driver = self.firefox_driver

            for i in range(BROWSER_CAPTURE_COUNT):
                f_name = self._file_path_gen(capture_folder, name, driver, i)
                capture_files.append(f_name)
                self._start_capture(f_name)
                current_driver.get(url)
                self._stop_capture()
                current_driver.get(BLANK_PAGE)

                # if i % 2 == 0:
                #     if driver == 'chrome':
                #         delete_cache_chrome(current_driver)
                # else:
                current_driver.quit()
                if driver == 'chrome':
                    current_driver = self.restart_chrome()
                else:
                    current_driver = self.restart_firefox()

        return capture_files

    @staticmethod
    def _file_path_gen(capture_folder, name, browser, test_run):
        return os.path.join(capture_folder, name + '-' + browser + '-' + str(test_run) + FILE_EXT)

    def _start_capture(self, file):
        if self.active_capture is not None:
            print('[ERROR]: Cannot run multiple TShark captures at the same time')
            return

        self.active_capture = subprocess.Popen(["tshark", "-q", "-w", file], stderr=subprocess.PIPE)
        while True:
            line = self.active_capture.stderr.readline()
            if line is None:
                break
            if b'Capturing on' in line.rstrip():
                break
        time.sleep(2)

    def _stop_capture(self):
        if self.active_capture is not None:
            if self.active_capture.poll() is not None:
                print('[WARNING]: TShark unexpetedly quitted earlier, capture of fingerprint may be incomplete!')
            else:
                self.active_capture.terminate()

            self.active_capture = None
