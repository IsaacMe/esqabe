
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
