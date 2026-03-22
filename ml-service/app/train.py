"""
Training script for the CNN-LSTM XSS detection model.

Papers [3] (Tadhani et al.) and [4] (Li et al.):
  - Character-level tokenization (Paper [4])
  - CNN-LSTM hybrid architecture (Paper [3])
  - 10 epochs, Adam optimiser, binary cross-entropy loss

Usage:
    python -m app.train
"""

from __future__ import annotations

import os
import sys

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import numpy as np  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)

from .data_prep import load_dataset, save_vocab  # noqa: E402
from .model import WEIGHTS_PATH, build_model  # noqa: E402

# ---------------------------------------------------------------------------
# Training configuration
# ---------------------------------------------------------------------------
EPOCHS = 10
BATCH_SIZE = 32


def main() -> None:
    print("=" * 60)
    print("XSS CNN-LSTM Model Training — Papers [3] & [4]")
    print("=" * 60)

    # 1. Load & prepare data
    print("\n[1/4] Loading dataset and building character vocabulary...")
    X_train, X_test, y_train, y_test, vocab = load_dataset()
    print(f"  Vocabulary size : {len(vocab)}")
    print(f"  Training samples: {len(X_train)}")
    print(f"  Test samples    : {len(X_test)}")
    print(f"  Class balance   : {y_train.sum()} XSS / {len(y_train) - y_train.sum()} benign (train)")

    # 2. Save vocabulary
    print("\n[2/4] Saving character vocabulary...")
    save_vocab(vocab)
    print(f"  Saved to {save_vocab.__defaults__}")  # type: ignore[attr-defined]

    # 3. Build & train model
    print("\n[3/4] Building and training model...")
    model = build_model(vocab_size=len(vocab))
    model.summary()

    model.fit(
        X_train,
        y_train,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=0.15,
        verbose=1,
    )

    # 4. Evaluate
    print("\n[4/4] Evaluating on test set...")
    y_prob = model.predict(X_test, verbose=0).flatten()
    y_pred = (y_prob > 0.5).astype(int)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print(f"\n  Accuracy  : {acc:.4f}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['benign', 'xss'])}")

    # 5. Save weights
    WEIGHTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    model.save_weights(str(WEIGHTS_PATH))
    print(f"Model weights saved to {WEIGHTS_PATH}")
    print("Training complete.")


if __name__ == "__main__":
    main()
