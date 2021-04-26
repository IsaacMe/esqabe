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

import dpkt
from .utils import inet_to_str, is_from_wiki
import pandas as pd
from .search_trace import PacketDC


DNS_PORT = 53
TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1


class WikiTrace:
    def __init__(self, pcap, url, id):
        self.id = id
        self.url = url
        self.pcap = pcap
        self.wiki_ips = set()
        self.ip_domain_mapping = set()
        self.current_handling = None
        self.packets = []
        self.packets_df = None

    def get_packets_df(self):
        self._init_df()
        return self.packets_df

    def get_ip_domain_mapping(self):
        return self.ip_domain_mapping

    def ip_to_domain(self, ip):
        for ip_domain in self.ip_domain_mapping:
            if ip_domain[0] == ip:
                return ip_domain[1]

        return None

    def extend_wiki_ips(self, ips):
        self.wiki_ips.update(ips)

    def parse(self):
        for ts, buf in dpkt.pcapng.Reader(open(self.pcap, 'rb')):
            eth = dpkt.ethernet.Ethernet(buf)
            self.current_handling = {PacketDC.FRAME_TIME.value: ts * 1000}

            if self.__handle_ip(eth, ts):
                self.packets.append(self.current_handling)

        self.current_handling = None
        self.__filter_out()

    def insert_df(self, df):
        self.packets_df = df

    def get_id(self):
        return self.id

    def get_url(self):
        return self.url

    def get_histogram(self):
        # TODO Could be written more efficiently using pandas
        self._init_df()
        histogram = {}
        for index, row in self.packets_df.iterrows():
            direction = '1'
            if row[PacketDC.DST_IP.value] in self.wiki_ips:
                direction = '0'

            k = direction + '-' + str(row[PacketDC.FRAME_LENGTH.value])

            if k in histogram:
                histogram[k] += 1
            else:
                histogram[k] = 1

        return histogram

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

            self.current_handling[PacketDC.SRC_PORT.value] = tcp.sport
            self.current_handling[PacketDC.DST_PORT.value] = tcp.dport

            return self.__handle_tls(tcp, ip_dst, ip_src)
        else:
            return False

    def __handle_tls(self, tcp, ip_dst_str, ip_src_str):
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
                            if is_from_wiki(domain_name):
                                self.ip_domain_mapping.add((ip_dst_str, domain_name))
                                self.wiki_ips.add(ip_dst_str)

        return True

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
                if answer.type == dpkt.dns.DNS_A and is_from_wiki(str.lower(answer.name)):
                    self.ip_domain_mapping.add((inet_to_str(answer.ip), str.lower(answer.name)))
                    self.wiki_ips.add(inet_to_str(answer.ip))
                elif answer.type == dpkt.dns.DNS_AAAA and is_from_wiki(str.lower(answer.name)):
                    self.ip_domain_mapping.add((inet_to_str(answer.ip6), str.lower(answer.name)))
                    self.wiki_ips.add(inet_to_str(answer.ip6))
            return True
        else:
            return False

    def __filter_out(self):
        self._init_df()
        self.packets_df = self.packets_df[self.packets_df[PacketDC.DST_IP.value].isin(self.wiki_ips) | self.packets_df[PacketDC.SRC_IP.value].isin(self.wiki_ips)]


