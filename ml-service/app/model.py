"""
CNN-LSTM XSS detection model
Architecture:
  Embedding → Conv1D → MaxPool1D → Bidirectional LSTM → Dense → Dropout → Sigmoid
The CNN extracts local n-gram character patterns, and the
bidirectional LSTM captures sequential dependencies.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Optional
import numpy as np
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2" 
import tensorflow as tf 
from tensorflow import keras 

from .data_prep import MAX_LENGTH, VOCAB_PATH, load_vocab, tokenize

# Paths
MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
WEIGHTS_PATH = MODEL_DIR / "xss_cnn_lstm.weights.h5"

# Sliding window stride for inputs longer than MAX_LENGTH.
# Overlapping windows ensure payloads injected after benign padding are caught.
WINDOW_STRIDE = 100

# Model builder
def build_model(vocab_size: int) -> keras.Model:
    """Construct the CNN-LSTM binary classifier."""
    model = keras.Sequential([
        keras.layers.Input(shape=(MAX_LENGTH,)),
        keras.layers.Embedding(
            input_dim=vocab_size,
            output_dim=64,
        ),
        # CNN feature extraction
        keras.layers.Conv1D(filters=128, kernel_size=3, activation="relu"),
        keras.layers.MaxPooling1D(pool_size=2),
        # Sequential pattern learning
        keras.layers.Bidirectional(keras.layers.LSTM(64)),
        keras.layers.Dense(64, activation="relu"),
        keras.layers.Dropout(0.5),
        keras.layers.Dense(1, activation="sigmoid"),
    ])
    model.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


# Singleton detector used by the FastAPI app
class XSSDetector:
    """Loads a trained model + vocabulary and exposes a predict() method."""

    def __init__(self) -> None:
        self._model: Optional[keras.Model] = None
        self._vocab: Optional[dict[str, int]] = None
        self._loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def load(self) -> None:
        """Load saved weights and vocabulary from disk."""
        if not WEIGHTS_PATH.exists() or not VOCAB_PATH.exists():
            return
        self._vocab = load_vocab()
        vocab_size = len(self._vocab)
        self._model = build_model(vocab_size)
        self._model.load_weights(str(WEIGHTS_PATH))
        self._loaded = True

    def _score_windows(self, text: str) -> float:
        """Tokenize *text* using a sliding window and return the worst-case
        (maximum) XSS probability across all windows.

        Inputs shorter than MAX_LENGTH are evaluated as a single window.
        For longer inputs, windows of size MAX_LENGTH advance by WINDOW_STRIDE
        characters so that payloads hidden after benign padding cannot escape
        detection by exploiting the model's fixed sequence length.
        """
        if self._model is None or self._vocab is None:
            return 0.0

        starts = range(0, max(1, len(text) - MAX_LENGTH + 1), WINDOW_STRIDE)
        chunks = [text[s: s + MAX_LENGTH] for s in starts]
        # Always include the tail window so the very end is not skipped
        if len(text) > MAX_LENGTH and len(text) - MAX_LENGTH not in starts:
            chunks.append(text[-MAX_LENGTH:])

        batch = np.stack([tokenize(c, self._vocab) for c in chunks])
        probs = self._model.predict(batch, verbose=0).flatten()
        return float(probs.max())

    def predict(self, text: str) -> dict:
        """Run inference on a single text input.
        Returns {"is_xss": bool, "confidence": float, "details": str}.

        Long inputs (> MAX_LENGTH chars) are scanned with a sliding window so
        that attackers cannot bypass detection by prepending benign padding.
        """
        if not self._loaded or self._model is None or self._vocab is None:
            return {
                "is_xss": False,
                "confidence": 0.0,
                "details": "Model not loaded   falling back to safe default",
            }

        prob = self._score_windows(text)
        is_xss = prob > 0.7

        details = (
            f"XSS detected (confidence {prob:.4f})" if is_xss
            else f"Input appears benign (confidence {prob:.4f})"
        )
        return {"is_xss": is_xss, "confidence": round(prob, 4), "details": details}

# Module-level singleton
detector = XSSDetector()
