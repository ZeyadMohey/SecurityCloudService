"""
CNN-LSTM XSS detection model — Papers [3] (Tadhani et al.) and [4] (Li et al.).

Architecture:
  Embedding → Conv1D → MaxPool1D → Bidirectional LSTM → Dense → Dropout → Sigmoid

The CNN extracts local n-gram character patterns (Paper [3]), and the
bidirectional LSTM captures sequential dependencies (Paper [4]).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import numpy as np

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"  # suppress TF info/warning noise
import tensorflow as tf  # noqa: E402
from tensorflow import keras  # noqa: E402

from .data_prep import MAX_LENGTH, VOCAB_PATH, load_vocab, tokenize  # noqa: E402

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
WEIGHTS_PATH = MODEL_DIR / "xss_cnn_lstm.weights.h5"


# ---------------------------------------------------------------------------
# Model builder
# ---------------------------------------------------------------------------

def build_model(vocab_size: int) -> keras.Model:
    """Construct the CNN-LSTM binary classifier.

    Paper [3]: Conv1D for local pattern extraction
    Paper [4]: Bidirectional LSTM for sequential learning
    """
    model = keras.Sequential([
        keras.layers.Input(shape=(MAX_LENGTH,)),
        keras.layers.Embedding(
            input_dim=vocab_size,
            output_dim=64,
        ),
        # CNN feature extraction — Paper [3]
        keras.layers.Conv1D(filters=128, kernel_size=3, activation="relu"),
        keras.layers.MaxPooling1D(pool_size=2),
        # Sequential pattern learning — Paper [4]
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


# ---------------------------------------------------------------------------
# Singleton detector used by the FastAPI app
# ---------------------------------------------------------------------------

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

    def predict(self, text: str) -> dict:
        """Run inference on a single text input.

        Returns {"is_xss": bool, "confidence": float, "details": str}.
        """
        if not self._loaded or self._model is None or self._vocab is None:
            return {
                "is_xss": False,
                "confidence": 0.0,
                "details": "Model not loaded — falling back to safe default",
            }

        tokens = tokenize(text, self._vocab)
        tokens = np.expand_dims(tokens, axis=0)  # batch dim

        prob = float(self._model.predict(tokens, verbose=0)[0][0])
        is_xss = prob > 0.7  # threshold per CLAUDE.md spec

        details = (
            f"XSS detected (confidence {prob:.4f})" if is_xss
            else f"Input appears benign (confidence {prob:.4f})"
        )
        return {"is_xss": is_xss, "confidence": round(prob, 4), "details": details}


# Module-level singleton — loaded once at import / startup
detector = XSSDetector()
