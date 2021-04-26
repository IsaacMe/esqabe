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


from .util import load_pcap
from .detection import detect_website_keystrokes, detect_keystrokes
from .tokenization import tokenize_words
import math


def mini_kreep(pcap, max_word_len, website=None):
    # Load the pcap
    pcap, pcap_in = load_pcap(pcap, website)

    # Load the dictionary, language, and timing models
    #language, words = load_language(language)

    if website is None:
        website, keystrokes = detect_website_keystrokes(pcap)
    else:
        keystrokes = detect_keystrokes(pcap, website)

    # Detect if a keystroke is detected outside the 'normal' range
    spikes = estimate_network_spikes(pcap_in)
    number_of_packets = len(keystrokes.index)
    for spike in spikes:
        spike_grouped = keystrokes['frame_time'] <= spike
        s = spike_grouped.sum()
        if s == number_of_packets:  # All packets smaller than peak
            break
        elif s == 0:  # All packets larger then peak (check next)
            continue
        elif math.floor(2 * number_of_packets / 3) < s < number_of_packets:  # More than 2/3 of the packets smaller than peak
            keystrokes = keystrokes[spike_grouped]
            print('Removed', number_of_packets - s, 'potential keystrokes at the back as they were probably misread')
            break
        elif 0 < s < math.ceil(1 * number_of_packets / 3):  # Less than 1/3 of the packets is in front of a peak
            keystrokes = keystrokes[~spike_grouped]
            print('Removed', s, 'potential keystrokes in the front as they were probably misread')
        else:
            print('Peak in middle of search string detected, possibly false detection')

    # Detect space keys to create word tokens
    # keystrokes['token'] = tokenize_words(keystrokes, website, max(words.keys()))
    keystrokes['token'] = tokenize_words(keystrokes, website, max_word_len)

    max_token = max(keystrokes['token'])
    word_lengths = [-1 for i in range(0, max_token)]
    word_lengths.append(0)
    for tok in keystrokes['token']:
        word_lengths[tok] += 1

    return word_lengths, keystrokes['frame_time'].max(), keystrokes['dst'].max(), keystrokes['frame_length'].max(), pcap


def estimate_network_spikes(trace):
    length_group_size = 500
    agg_lens = trace.groupby(trace['frame_time'] // length_group_size * length_group_size)['frame_length'].sum()
    return agg_lens[agg_lens > 100000].keys()
