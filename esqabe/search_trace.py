import dpkt
import socket
from .utils import inet_to_str
import pandas as pd
from enum import Enum


DNS_PORT = 53
TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1


class InternalPacketTypes(Enum):
    DATA = 0
    TLS_CLIENT_HELLO_SNI = 1


class PacketDC(Enum):
    SRC_IP = 'src_ip'
    SRC_PORT = 'src_port'
    DST_IP = 'dst_ip'
    DST_PORT = 'dst_port'
    FRAME_TIME = 'frame_time'
    FRAME_LENGTH = 'frame_length'
    PROTOCOL = 'protocol'
    PACKET_TYPE = 'packet_type'
    PACKET_TYPE_CONTENT = 'packet_type_content'


class SearchTrace:
    def __init__(self, pcap):
        self.pcap = pcap
        self.ips = set()
        self.ip_domain_mapping = set()
        self.minimum_time = 0
        self.google_packets = []
        self.current_handling = None
        self.packets = []
        self.packets_df = None

    def get_packets_df(self):
        self._init_df()
        return self.packets_df

    def set_interesting_minimum_time(self, minimum_time):
        self.minimum_time = minimum_time

    def get_ip_domain_mapping(self):
        return self.ip_domain_mapping

    def get_data_from_google_packets(self):
        return self.google_packets

    def get_unrecognised_ips(self):
        unreconised_ips = []
        for ip in self.ips:
            found = False
            for ip_domain in self.ip_domain_mapping:
                if ip == ip_domain[0]:
                    found = True
                    break
            if not found:
                unreconised_ips.append(ip)
        return unreconised_ips

    def ip_to_domain(self, ip):
        for ip_domain in self.ip_domain_mapping:
            if ip_domain[0] == ip:
                return ip_domain[1]

        return None

    def make_website_guess(self):
        self._init_df()
        guesses = []
        length_group_size = 1000
        agg_lens = self.packets_df.groupby(self.packets_df.frame_time // length_group_size * length_group_size)[PacketDC.FRAME_LENGTH.value].sum()
        sni = self.packets_df.loc[self.packets_df[PacketDC.PACKET_TYPE.value] == InternalPacketTypes.TLS_CLIENT_HELLO_SNI.value]
        sni.reset_index(inplace=True)
        max_s = agg_lens.last_valid_index()

        prev = None
        prev_selected_but_filtered = False
        visit_active = False
        for i, row in sni.iterrows():
            if row[PacketDC.FRAME_TIME.value] < self.minimum_time:
                continue

            next_len = 0
            this_time = row[PacketDC.FRAME_TIME.value] // length_group_size * length_group_size
            for j in range(int(this_time), int(min(this_time + 4000, max_s)), length_group_size):
                if j in agg_lens.index:
                    next_len += agg_lens[j]

            # We suppose a user needs some seconds to skimm the page
            interesting = self.__is_intersting_domain(row[PacketDC.PACKET_TYPE_CONTENT.value]) and 'google' not in row[PacketDC.PACKET_TYPE_CONTENT.value]
            last_sni_is_long_ago = prev is None or row[PacketDC.FRAME_TIME.value] - prev[PacketDC.FRAME_TIME.value] > 3000

            if last_sni_is_long_ago:
                visit_active = False

            if not visit_active and interesting and next_len > 50000:
                guesses.append(
                    (row[PacketDC.PACKET_TYPE_CONTENT.value], row[PacketDC.PACKET_TYPE_CONTENT.FRAME_TIME.value]))
                visit_active = True

            if interesting:
                prev = row

        return guesses

    def parse(self):
        for ts, buf in dpkt.pcapng.Reader(open(self.pcap, 'rb')):
            eth = dpkt.ethernet.Ethernet(buf)
            self.current_handling = {PacketDC.FRAME_TIME.value: ts * 1000,
                                     PacketDC.PACKET_TYPE.value: InternalPacketTypes.DATA.value}

            if self.__handle_ip(eth, ts):
                self.packets.append(self.current_handling)

        self.current_handling = None
        self.__filter_out()

    def _init_df(self, force=False):
        if self.packets_df is None or force:
            self.packets_df = pd.DataFrame(self.packets, columns=[e.value for e in PacketDC])

    # --- HANDLE FUNCTIONS ---
    # Replies True if handled, false if not
    def __handle_ip(self, eth, ts):
        if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip = eth.data
            self.current_handling[PacketDC.SRC_IP.value] = inet_to_str(ip.src)
            self.current_handling[PacketDC.DST_IP.value] = inet_to_str(ip.dst)
            self.current_handling[PacketDC.FRAME_LENGTH.value] = len(ip.data)
            self.current_handling[PacketDC.PROTOCOL.value] = ip.p

            return self.__handle_tcp(ip, ts) or self.__handle_udp(ip)
        else:
            return False

    def __handle_tcp(self, ip, ts):
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data

            ip_src = self.current_handling[PacketDC.SRC_IP.value]
            ip_dst = self.current_handling[PacketDC.DST_IP.value]
            self.ips.add(ip_src)
            self.ips.add(ip_dst)

            self.current_handling[PacketDC.SRC_PORT.value] = tcp.sport
            self.current_handling[PacketDC.DST_PORT.value] = tcp.dport

            return self.__handle_tls(tcp, ip_dst)
            # Handled in kreep from now self.__handle_google(ip, ts)
        else:
            return False

    def __handle_tls(self, tcp, ip_dst_str):
        if len(tcp.data) <= 0:
            return False

        try:
            tls_records, i = dpkt.ssl.tls_multi_factory(tcp.data)
        except (dpkt.ssl.SSL3Exception, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return False

        if i < len(tcp.data):
            pass

        for record in tls_records:
            if record.type == TLS_HANDSHAKE:
                try:
                    tls_handshake = dpkt.ssl.TLSHandshake(record.data)
                except (dpkt.ssl.SSL3Exception, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    return False

                if tls_handshake.type == TLS_CLIENT_HELLO and hasattr(tls_handshake.data, 'extensions'):
                    for tls_extension in tls_handshake.data.extensions:
                        if tls_extension[0] == 0:
                            domain_name = str.lower(tls_extension[1][5:].decode("ascii"))
                            self.current_handling[PacketDC.PACKET_TYPE.value] =\
                                InternalPacketTypes.TLS_CLIENT_HELLO_SNI.value
                            self.current_handling[PacketDC.PACKET_TYPE_CONTENT.value] = domain_name
                            self.ip_domain_mapping.add((ip_dst_str, domain_name))

        return True

    def __handle_google(self, ip, ts):
        tcp = ip.data

        if len(tcp.data) <= 0 or not self.__is_from_google(ip.dst):
            return False

        self.google_packets.append((inet_to_str(ip.src) + ':' + tcp.sport, inet_to_str(ip.dst) + ':' + tcp.dport, ts*1000, len(tcp.data), ip.p))
        return False # Returns False because not sure if from Google

    def __handle_udp(self, ip):
        if ip.p == dpkt.ip.IP_PROTO_UDP:
            self.current_handling[PacketDC.SRC_PORT.value] = ip.data.sport
            self.current_handling[PacketDC.DST_PORT.value] = ip.data.dport
            return self.__handle_dns(ip.data)
        else:
            return False

    def __handle_dns(self, udp):
        if udp.sport == 53:
            try:
                dns = dpkt.dns.DNS(udp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                return False

            for answer in dns.an:  # TODO Add CNAME?
                if answer.type == dpkt.dns.DNS_A:
                    self.ip_domain_mapping.add((inet_to_str(answer.ip), str.lower(answer.name)))
                elif answer.type == dpkt.dns.DNS_AAAA:
                    self.ip_domain_mapping.add((inet_to_str(answer.ip6), str.lower(answer.name)))
            return True
        else:
            return False

    def __filter_out(self):
        ips_of_bigger = set()
        for ts, buf in dpkt.pcapng.Reader(open(self.pcap, 'rb')):
            eth = dpkt.ethernet.Ethernet(buf)

            if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                ip = eth.data

                if self.__is_interesting_ip(ip, ts * 1000):  # Definition of filter
                    ips_of_bigger.add(inet_to_str(ip.src))
                    ips_of_bigger.add(inet_to_str(ip.dst))

        self.ips = self.ips.intersection(ips_of_bigger)

        for ip_domain in self.ip_domain_mapping:
            if not self.__is_intersting_domain(ip_domain[1]):
                try:
                    self.ips.remove(ip_domain[0])
                except KeyError:
                    pass

        self.ip_domain_mapping = [ip_domain for ip_domain in self.ip_domain_mapping if ip_domain[0] in ips_of_bigger
                                  and self.__is_intersting_domain(ip_domain[1])]

    def __is_interesting_ip(self, ip, time):
        # Tested package sizes
        return ip.p == dpkt.ip.IP_PROTO_TCP and len(ip) >= 1240 and time > self.minimum_time

    def __is_intersting_domain(self, domain):
        # Avoids certain computer domains
        avoid_keywords = ["cdn", "static", "doubleclick", "api.", "cloudfront", "map.fastly.net", "googleapis.com",
                          "code.jquery.com", "hit.gemius.pl", "akamaiedge.net", "dropbox.com", "hotjar.com",
                          "opera.com", "s.section.io", "adobess.com", "omtrdc.net", "demdex.net", "adservice.google",
                          "global.fastly.net", "hello.myfonts.net", "adobedtm.com", "ping.chartbeat.net",
                          "drive.google.com", "resources.jetbrains.com", "js-agent.newrelic.com",
                          "googletagmanager.com", "stackstorage.com", "mail.me.com", "ytimg.com", "mozilla.cloudflare-dns.com", "services.mozilla.com", "telemetry.mozilla.org"]
        return not any(keyword in domain for keyword in avoid_keywords)

    def __is_from_google(self, ip):
        # TODO: Use OpenKnock? But does it work with IPv6?
        return socket.gethostbyaddr(ip)[0].endswith('1e100.net')
