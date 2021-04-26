# ---------------------------------------------------------------
# kreep - keystroke recognition and entropy elimination program
#   by Vinnie Monaco
#   www.vmonaco.com
#   contact AT vmonaco DOT com
#
#   Licensed under GPLv3
#
# ----------------------------------------------------------------
# Changes made by Isaac Meers
#   - Improved detection of Google Search traffic
#   - Reduced version of Kreep, only detection and tokenization
# ----------------------------------------------------------------


import dpkt
import socket
import pandas as pd

IS_GOOGLE = {}

INCOMING = 0
OUTGOING = 1
UNKNOWN = 2


def ip_to_str(inet):
    """Convert inet object to a string
        Source: https://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html#mac_addr
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def load_pcap(fname, website):
    """
    Load a pcap (ng) into a pandas DataFrame
    """
    rows = []
    rows_in = []
    for ts, buf in dpkt.pcapng.Reader(open(fname, 'rb')):
        row, dir = parse_eth(buf, ts, website)
        if dir == INCOMING:
            rows_in.extend(row)
        else:
            rows.extend(row)
    df = pd.DataFrame(rows, columns=['src', 'dst', 'frame_time', 'frame_length', 'protocol'])
    df_in = pd.DataFrame(rows_in, columns=['src', 'dst', 'frame_time', 'frame_length', 'protocol'])
    return df, df_in


def parse_eth(buf, ts, website):
    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
        return parse_ip(eth.data, ts, website)
    return [], UNKNOWN


def parse_ip(ip, ts, website):
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        dir = UNKNOWN
        can_parse = website != 'google'

        if website == 'google' and is_from_google(ip_to_str(ip.dst)):
            can_parse = True
            dir = OUTGOING
        elif website == 'google' and is_from_google(ip_to_str(ip.src)):
            can_parse = True
            dir = INCOMING

        if can_parse:
            return parse_tcp(ip.data, ts, ip, dir), dir
    return [], UNKNOWN


def parse_tcp(tcp, ts, ip, dir):
    if len(tcp.data) > 0:  # Ignores HTTP, only HTTPS, currently no QUIC support
        if dir == INCOMING and tcp.sport == 443:
            return [(ip_to_str(ip.src) + ':' + str(tcp.sport),
                     ip_to_str(ip.dst) + ':' + str(tcp.dport), ts * 1000,
                     len(tcp.data), ip.p)]
        elif tcp.dport == 443:
            return parse_tls(tcp, ts, ip)

    return []


def parse_tls(tcp, ts, ip):
    try:
        tls_records, i = dpkt.ssl.tls_multi_factory(tcp.data)
    except (dpkt.ssl.SSL3Exception, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return []

    if i < len(tcp.data):
        # TODO Possibly not read all TLS Records due to fragmentation
        pass

    results = []
    for record in tls_records:
        if record.type == 23:  # TLS APP DATA
            results.append((ip_to_str(ip.src) + ':' + str(tcp.sport),
                            ip_to_str(ip.dst) + ':' + str(tcp.dport), ts * 1000,
                            len(record.data), ip.p))

    return results


def is_from_google(ip):
    if ip in IS_GOOGLE:
        return IS_GOOGLE[ip]

    try:
        is_google = socket.gethostbyaddr(ip)[0].endswith('1e100.net')
        IS_GOOGLE[ip] = is_google
        return is_google
    except socket.herror:
        IS_GOOGLE[ip] = False
        return False
