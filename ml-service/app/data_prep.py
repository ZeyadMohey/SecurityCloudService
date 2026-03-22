"""
Data preparation for XSS detection with character-level tokenization.
maps each character to an integer index, pads or truncates sequences to a fixed max_length, 
and builds a character vocabulary from the training corpus(Li et al.).
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Tuple
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# Constants
MAX_LENGTH = 200    
VOCAB_PATH = Path(__file__).resolve().parent.parent / "models" / "char_vocab.json"
DATASET_PATH = Path(__file__).resolve().parent.parent / "data" / "xss_dataset.csv"

# Vocabulary helpers
def build_vocab(texts: pd.Series) -> dict[str, int]:
    """Build a character → integer mapping from the training corpus.

    Index 0 is reserved for padding, 1 for unknown characters.
    """
    chars: set[str] = set()
    for text in texts:
        chars.update(str(text))
    vocab: dict[str, int] = {"<PAD>": 0, "<UNK>": 1}
    for idx, ch in enumerate(sorted(chars), start=2):
        vocab[ch] = idx
    return vocab


def save_vocab(vocab: dict[str, int], path: Path | None = None) -> None:
    path = path or VOCAB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(vocab, fh, ensure_ascii=False)


def load_vocab(path: Path | None = None) -> dict[str, int]:
    path = path or VOCAB_PATH
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

# Tokenisation
def tokenize(text: str, vocab: dict[str, int], max_len: int = MAX_LENGTH) -> np.ndarray:
    """Character-level tokenization
    Each character is mapped to its vocabulary index.  Unknown characters
    map to <UNK> (index 1).  Sequences shorter than *max_len* are zero-padded
    on the right; longer sequences are truncated.
    """
    unk = vocab.get("<UNK>", 1)
    ids = [vocab.get(ch, unk) for ch in str(text)[:max_len]]
    # Pad to max_len
    ids += [0] * (max_len - len(ids))
    return np.array(ids, dtype=np.int32)


def tokenize_batch(texts: pd.Series, vocab: dict[str, int], max_len: int = MAX_LENGTH) -> np.ndarray:
    """Tokenize an entire Series of texts into a 2-D array."""
    return np.stack([tokenize(t, vocab, max_len) for t in texts])

# Dataset loading
def load_dataset(
    path: Path | None = None,
    test_size: float = 0.2,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, dict[str, int]]:
    """
    Load the CSV dataset, build vocab, tokenize, and split.
    Returns (X_train, X_test, y_train, y_test, vocab).
    """
    path = path or DATASET_PATH
    # XSS payloads often contain commas, so we parse from the right:
    # the label is always the last comma-separated field (0 or 1).
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        header = fh.readline()  # skip header
        for line in fh:
            line = line.rstrip("\n\r")
            if not line:
                continue
            # Split on the *last* comma to separate text from label
            idx = line.rfind(",")
            if idx == -1:
                continue
            text = line[:idx]
            label_str = line[idx + 1:]
            if label_str not in ("0", "1"):
                continue
            # Strip surrounding quotes if CSV-quoted
            if text.startswith('"') and text.endswith('"'):
                text = text[1:-1].replace('""', '"')
            rows.append({"text": text, "label": int(label_str)})
    df = pd.DataFrame(rows)

    X_text = df["text"]
    y = df["label"].values

    # Build vocab from full corpus (safe character vocab, no label leakage)
    vocab = build_vocab(X_text)
    X = tokenize_batch(X_text, vocab)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y,
    )
    return X_train, X_test, y_train, y_test, vocab
