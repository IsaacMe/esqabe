import pandas as pd
from .search_trace import PacketDC
from .fingerprint_visitor import FingerprintVisitor
from .wiki_trace import WikiTrace
from .fingerprinting.classifiers.LiberatoreClassifier import LiberatoreClassifier
import math
import wikipedia
import tempfile
import re

TIME_LOAD_UNTIL_CLICK = 4000
KNOWN_WIKI_NAMES = ['wikipedia.org', 'wikimedia.org']
GUESS_ID = 'guess'
HARD_WIKI_DISAMBIGUATION_LIMIT = 5


class WikiFingerprintComparer:
    def __init__(self) -> None:
        super().__init__()
        self.wiki_ips = []

    @staticmethod
    def is_from_wiki(domain):
        return any(wiki in domain for wiki in KNOWN_WIKI_NAMES)

    def feed_with_ip_domains(self, ip_domain_mapping):
        for ip_domain in ip_domain_mapping:
            if self.is_from_wiki(ip_domain[1]):
                self.wiki_ips.append(ip_domain[0])

    def add_wiki_ips(self, wiki_ips):
        self.wiki_ips.extend(wiki_ips)

    def set_wiki_domain(self, domain):
        splitted = domain.split('.')

        if splitted[1] != 'wikipedia':
            raise ValueError('"' + domain + '" is not a Wikipedia domain.')

        wikipedia.set_lang(splitted[0])

    def compare(self, terms, packets: pd.DataFrame, ts):
        interesting_packets = self._filter_interesting(packets, ts)
        question = WikiTrace(None, 'question', GUESS_ID)
        question.insert_df(interesting_packets)
        urls = set()
        url_term_dict = {}

        for term in terms:
            term_urls = self._generate_wiki_urls(term)
            if len(term_urls) == 0 and term.isupper():
                term_urls = self._generate_wiki_urls(term.lower())
            print(term, term_urls)
            urls.update(term_urls)
            url_term_dict.update(dict(term_urls))

        if len(urls) == 1:
            url = urls.pop()
            return url[1], url[0]
        elif len(urls) < 1:
            return None, None

        fp_visitor = FingerprintVisitor()
        wiki_traces = []
        with tempfile.TemporaryDirectory() as temp_dir:
            capture_files = {}

            for url in urls:
                print('Tracing:', url, '...')
                capture_files[url[0]] = fp_visitor.generate_fingerprint(url[0], temp_dir)

            id_pattern = re.compile(r'[\W_]+')
            for page in capture_files:
                id = id_pattern.sub('', page.split('/')[-1])
                wiki_ips = set()
                for cap in capture_files[page]:
                    trace = WikiTrace(cap, page, id)
                    trace.extend_wiki_ips(wiki_ips)
                    trace.parse()
                    wiki_ips = trace.wiki_ips
                    wiki_traces.append(trace)

        train_instances = []
        test_instances = [LiberatoreClassifier.traceToInstance(question)]

        for trace in wiki_traces:
            train_instances.append(LiberatoreClassifier.traceToInstance(trace))

        print('Feeding to classifier')
        answers = LiberatoreClassifier.classify('testje', train_instances, test_instances)
        ans = answers[0][1].decode('utf-8')         # Normally only 1 answer

        for trace in wiki_traces:
            if trace.get_id() == ans:
                return url_term_dict[trace.get_url()], trace.get_url()

        return None, None

    def _filter_interesting(self, packets: pd.DataFrame, ts):
        poss_wiki_packets = packets[(packets[PacketDC.FRAME_TIME.value] >= ts) & (packets[PacketDC.DST_IP.value].isin(self.wiki_ips) | packets[PacketDC.SRC_IP.value].isin(self.wiki_ips))]
        shifted = poss_wiki_packets[PacketDC.FRAME_TIME.value].shift(-1, fill_value=math.inf)
        max_time = poss_wiki_packets[poss_wiki_packets[PacketDC.FRAME_TIME.value] + TIME_LOAD_UNTIL_CLICK < shifted][PacketDC.FRAME_TIME.value].iloc[0]
        return poss_wiki_packets[poss_wiki_packets[PacketDC.FRAME_TIME.value] <= max_time]

    def _generate_wiki_urls(self, term, follow_disambiguation=True):
        try:
            page = wikipedia.page(term, auto_suggest=False)
            return {(page.url, page.title)}
        except wikipedia.DisambiguationError as e:
            pages = set()

            if follow_disambiguation:
                for page in e.options:
                    pages.update(self._generate_wiki_urls(page, False))

                    if len(pages) >= HARD_WIKI_DISAMBIGUATION_LIMIT:
                        break

            return pages
        except wikipedia.PageError as e:
            return set()

