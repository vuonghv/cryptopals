"""
Compute fitness of text using n-gram statistics
"""
import math

class NGramScore(object):
    def __init__(self, ngram_file, sep=' '):
        """Load a file containing ngrams and counts, compute log probabilities
        """
        data = {}
        with open(ngram_file, 'r') as f:
            for line in f.readlines():
                key, count = line.split(sep)
                data[key] = int(count)
        self._L = len(key)
        self._N = sum(data.values())
        self._ngrams = {k: math.log10(v/self._N) for k, v in data.items()}
        self._floor = math.log10(0.01/self._N)

    def score(self, text: str) -> float:
        """Compute how likely a text is to english
        """
        fitness = 0.0
        for i in range(len(text) - self._L + 1):
            ngram = text[i:i+self._L]
            fitness += self._ngrams[ngram] if ngram in self._ngrams else self._floor
        return fitness

