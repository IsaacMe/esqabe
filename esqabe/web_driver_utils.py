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

def delete_cache(driver, browser):
    if browser == 'ff' or browser == 'firefox':
        print('[ERROR] Could not clear cache of FireFox. Use web profile.')
    elif browser == 'chrome' or browser == 'chromium':
        delete_cache_chrome(driver)
    else:
        print('[ERROR] Could not clear cache of unknown browser:', browser)


def delete_cache_chrome(driver):
    driver.execute_cdp_cmd('Network.clearBrowserCache', {})
    print('Cleared chrome cache')
