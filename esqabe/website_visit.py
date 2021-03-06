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
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException
import re


class WebsiteVisit:
    def __init__(self, url):
        self.url = url
        options = Options()
        options.headless = True
        self.driver = webdriver.Chrome(options=options)
        self.interesting_meta_tags = ['name', 'description', 'og:site_name', 'og:title', 'og:description',
                                     'twitter:title', 'twitter:description']

    def start_session(self):
        self.driver.get('http://' + self.url)

    def find_regex(self, patterns):
        selected_terms = []

        # TODO Check ID's, Img urls...

        text = self.driver.find_element_by_tag_name('body').get_attribute("innerText")

        try:
            title = self.driver.find_element_by_tag_name('title').get_attribute("innerText")
        except NoSuchElementException:
            title = ''

        if title == '403 Forbidden':
            return []

        try:
            meta_tags = self.driver.find_elements_by_tag_name('meta')
        except NoSuchElementException:
            meta_tags = []

        try:
            images = self.driver.find_elements_by_tag_name('img')
        except NoSuchElementException:
            images = []

        for pattern in patterns:
            full_pattern = "\\W(" + pattern + ")\\W"
            selected_terms.extend(re.findall(full_pattern, text))
            selected_terms.extend(re.findall(pattern, title))

            for meta_tag in meta_tags:
                if meta_tag.get_attribute('name') in self.interesting_meta_tags or meta_tag.get_attribute('itemprop')\
                        or meta_tag.get_attribute('property') in self.interesting_meta_tags:
                    selected_terms.extend(re.findall(full_pattern, ' ' + meta_tag.get_attribute('content') + ' '))

            for img in images:
                try:
                    if img.get_attribute('alt'):
                        selected_terms.extend(re.findall(full_pattern, ' ' + img.get_attribute('alt') + ' '))
                except StaleElementReferenceException:
                    continue

        return selected_terms

    def search_terms(self, terms):
        selected_terms = []

        for term in terms:
            try:
                elementl = self.driver.find_element_by_xpath("//*[contains(text(), '" + term + "')]")
            except NoSuchElementException as e:
                continue

            selected_terms.append(term)

        return selected_terms

    def end_session(self):
        self.driver.quit()



