from dpkt.compat import compat_ord
import socket

KNOWN_WIKI_NAMES = ['wikipedia.org', 'wikimedia.org']


def mac_addr(address):
    """Convert a MAC address to a readable/printable string
        Source: https://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html#mac_addr
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string
        Source: https://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html#mac_addr
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def is_from_wiki(domain):
    return any(wiki in domain for wiki in KNOWN_WIKI_NAMES)


def unify_case_in_counter(counter):
    counter_list = counter.most_common()
    while len(counter_list) > 0:
        current_word = counter_list.pop(0)[0]
        current_word_lower = current_word.lower()
        idx = len(counter_list) - 1

        while idx >= 0:
            if counter_list[idx][0].lower() == current_word_lower:
                del counter[counter_list[idx][0]]
                counter[current_word] += counter_list[idx][1]
                del counter_list[idx]
            idx -= 1

    return counter


def counter_threshold(counter, threshold):
    counter_list = counter.most_common()
    for val in counter_list:
        if val[1] <= threshold:
            del counter[val[0]]

    return counter
