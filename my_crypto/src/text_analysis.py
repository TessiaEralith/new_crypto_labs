import itertools
import json
import seaborn
import matplotlib.pyplot as plt
from scipy.stats import chi2


alphabet = sorted('йцукенгшщзхъфывапролджэячсмитьбю')


def create_frequency_dictionary(alphabet, m):
    if m < 3:
        combination_frequency = {"".join(i): 0 for i in itertools.product(alphabet, repeat=m)}
        return combination_frequency
    else: return {}

def count_mgram(text, alphabet, m):
    mgram = ''
    num_mgrams = 0
    combination_count = create_frequency_dictionary(alphabet, m)
    for letter in text:
        if letter in alphabet:
            if len(mgram) < m:
                mgram += letter
            else:
                mgram = mgram[1:] + letter
            if len(mgram) == m:
                num_mgrams += 1
                if combination_count.get(mgram) is not None: combination_count[mgram] += 1
                else: combination_count[mgram] = 0
        else:
            mgram = ''
    return combination_count, num_mgrams

def count_frequency(combination_count, num_mgrams):
    combination_frequency = {}
    for letter in combination_count:
        combination_frequency[letter] = combination_count[letter] / num_mgrams
    return combination_frequency

def chi(reference_frequency, check_text, error, alphabet, m):
    check_mgram, num_mgram = count_mgram(check_text, alphabet, m)
    assert len(reference_frequency) == len(check_mgram)
    k = len(reference_frequency)
    x = 0
    for i in reference_frequency:
        if reference_frequency[i] == 0:
            continue

        x += (((check_mgram[i] - reference_frequency[i] * num_mgram) ** 2) / (reference_frequency[i] * num_mgram))
        # print(check_mgram[i], reference_frequency[i] * num_mgram, x)
    x_crit = chi2.ppf((1 - error/100), k)
    # print(x_crit, x, k, num_mgram)
    if x_crit >= x:
        return "valid text"
    return "invalid text"


def text_analysis(text, m, alphabet='йцукенгшщзхъфывапролджэячсмитьбю'):
    combination_count, num_mgrams = count_mgram(text, alphabet, m)
    combination_frequency = count_frequency(combination_count, num_mgrams)
    # print(combination_frequency)
    if m == 1:
        seaborn.barplot(combination_frequency)
        combination_frequency = dict(sorted(combination_frequency.items(), key=lambda item: item[1], reverse=True))
        with open("../files/frequency", "w", encoding='utf-8') as f:
            json.dump(combination_frequency, f, indent=4, ensure_ascii=False)
        plt.show()
    else:
        combination_frequency = dict(sorted(combination_frequency.items(), key=lambda item: item[1], reverse=True))
        with open("../files/frequency", "w", encoding='utf-8') as f:
            json.dump(combination_frequency, f, indent=4, ensure_ascii=False)


# with open('../files/fourth_text', "r", encoding='utf-8') as f:
#     text = f.read().lower().replace('ё', 'е').replace(u'\xa0', u' ')
#
# text_analysis(text, 1, alphabet)
