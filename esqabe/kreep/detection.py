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

import numpy as np
import math


def google_rule(a, e, ta, te, tp):
    d = e - a[-1]

    if len(a) <= 2 and te - ta > 2500:
        return False

    if te - tp > 3000:
        return False

    # Only one decrease allowed, only possible if gs_mss appeard already
    # Dont know why decreases are allowed, so temp turned this of
    if False and d < 0:
        pd = np.diff(a)
        return len(a) >= 5 and (pd < 0).sum() <= 0 and (pd >= 4).sum() >= 1

    # No consecutive 0s
    if d == 0:
        return 0 not in np.diff(a[-2:])

    if d == 1:
        return True

    if d == 2:
        return True

    if d == 3:
        return True

    # Bigger increase is okay, if not to big!
    # Made bigger increase more exact, because of known gs_mss behaviour
    # if 25 > d >= 4:
    estimated_gsmssd = (a[-1] - a[0]) + 8 + 1
    if d > 4 and estimated_gsmssd + 5 > d > estimated_gsmssd - 5:
        pd = np.diff(a)
        return len(a) >= 5 and (pd >= 4).sum() <= 0

    return False


def baidu_rule(a, e, ta, te, tp):
    d = e - a[-1]

    if len(a) <= 2 and te - ta > 2000:
        return False

    if d >= 2 and d <= 30:
        return True

    return False


DETECTION_RULES = {
    'google': google_rule,
    'baidu': baidu_rule
}


def longest_dfa_sequence(a, t, append_rule):
    '''
    Find the longest subsequence accepted by a DFA. append_rule returns True or
    False to indicate whether the DFA that accepted sequence a can transition
    after appending element t
    '''
    n = len(a)
    L = [[] for _ in range(n)]
    idx = [[] for _ in range(n)]

    L[0].append(a[0])
    idx[0].append(0)

    for i in range(1, n):
        for j in range(i):
            if append_rule(L[j], a[i], t[j], t[i], t[idx[j][-1]]) and len(L[i]) < len(L[j]) + 1:
                L[i] = L[j].copy()
                idx[i] = idx[j].copy()

        L[i].append(a[i])
        idx[i].append(i)

    m = idx[0]
    if len(m) > 1:
        pdiff = L[0][-1] - L[0][-2]
    else:
        pdiff = math.inf

    for i in range(len(idx)):
        # Added extra rule which chooses the longest opportunity with the best match
        x = idx[i]
        if len(x) > 1:
            diff = L[i][-1] - L[i][-2]
        else:
            diff = math.inf
        if len(x) > len(m) or (len(x) == len(m) and diff < pdiff):
            m = x
            pdiff = diff

    return m


def detect_keystrokes(df, website):
    # At least the min size of a GET request
    df = df[df['frame_length'] > 100]

    result = []
    for src, dst, protocol in df[['src', 'dst', 'protocol']].drop_duplicates().values:
        df_dst = df[(df['src'] == src) & (df['dst'] == dst) & (df['protocol'] == protocol)]
        idx = longest_dfa_sequence(df_dst['frame_length'].values.tolist(), df_dst['frame_time'].values.tolist(),
                                   append_rule=DETECTION_RULES[website])

        if len(idx) > len(result):
            result = df_dst.iloc[idx]

    # Remove last, if Google makes big jump
    if website == 'google' and len(result) > 1 and np.diff(result.tail(2)['frame_length'])[0] >= 4:
        result.drop(result.tail(1).index, inplace=True)

    return result


def detect_website_keystrokes(df):
    '''
    Try to detect keystrokes using each rule, keep the longest
    '''
    website_out = ''
    keystrokes_out = []

    for website, rule in DETECTION_RULES.items():
        keystrokes = detect_keystrokes(df, website)

        if len(keystrokes) > len(keystrokes_out):
            keystrokes_out = keystrokes
            website_out = website

    return website_out, keystrokes_out
