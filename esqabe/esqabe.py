from .kreep import mini_kreep
from .search_trace import SearchTrace
from .website_visit import WebsiteVisit
from .wiki_fingerprint_comparer import WikiFingerprintComparer
from .utils import unify_case_in_counter, counter_threshold
from .esqabe_result import ESQABEResult
import collections


def esqabe(pcapng):
    result = ESQABEResult()

    print('-- STEP 1: Determine suggestions --')
    kreep_word_len, latest_package, google_dst, highest_frame, google_packets = mini_kreep(pcapng, 20, 'google')
    result.pattern = kreep_word_len


    print('Mini-Kreep:', kreep_word_len)
    print('Latest Timestamp:', latest_package / 1000)
    print('Google DST:', google_dst)

    print('-- STEP 2: Retrieve all domains / ips --')
    trace = SearchTrace(pcapng)
    trace.set_interesting_minimum_time(latest_package)
    trace.parse()

    print('Domains:', trace.get_ip_domain_mapping())
    print('Unkown IPs:', trace.get_unrecognised_ips())

    guesses = trace.make_website_guess()
    result.guessed_visits = guesses
    print('Guesses:', guesses)

    print('-- STEP 3: Visit domains and search for pattern of words --')

    pattern = generate_pattern(kreep_word_len)
    print('Pattern:', pattern)
    matches_per_site = {}
    matches_all = collections.Counter()
    for website_guess in guesses:
        visit_domain = website_guess[0]

        if WikiFingerprintComparer.is_from_wiki(visit_domain) or 'google' in visit_domain:
            continue

        visit = WebsiteVisit(visit_domain)
        visit.start_session()
        matches = collections.Counter(visit.find_regex([pattern]))
        matches_all.update(matches)
        visit.end_session()
        if len(matches) > 0:
            print('Found on', visit_domain, ':', matches)
            matches_per_site[visit_domain] = matches
    unify_case_in_counter(matches_all)
    counter_threshold(matches_all, 1)
    print('Found on websites:', matches_all)

    print('-- STEP 4: Use Wikipedia Fingerprinting when visited')
    wiki_comp = WikiFingerprintComparer()
    wiki_comp.feed_with_ip_domains(trace.get_ip_domain_mapping())
    for website_guess in guesses:
        visit_domain = website_guess[0]

        if not WikiFingerprintComparer.is_from_wiki(visit_domain):
            continue

        wiki_comp.set_wiki_domain(visit_domain)
        # Argument passable to filter only most common

        if len(matches_all) <= 0:
            break

        wiki_term, wiki_url = wiki_comp.compare(list(list(zip(*matches_all.most_common(3)))[0]), trace.get_packets_df(), website_guess[1])
        print('Visited WikiPage was probably', wiki_url)
        result.guessed_wiki = wiki_url
        if wiki_url is not None:
            matches_all[wiki_term] += 20

    print('-- STEP 5: Make ranking --')
    print(matches_all)
    result.result = matches_all

    return result


def generate_pattern(kreep_word_len):
    resulting_regex = ""

    for word in kreep_word_len:
        if len(resulting_regex) > 0:
            resulting_regex += ' '

        resulting_regex += "[\\w-]{" + str(word) + '}'

    return resulting_regex



