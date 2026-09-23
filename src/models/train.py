"""
Model Training and Evaluation Pipeline for PhishGuard.
Trains Logistic Regression, Random Forest, and Gradient Boosted Tree classifiers.
Evaluates Precision, Recall, F1, Accuracy, and ROC-AUC with strong emphasis on high recall.
Saves the champion model and evaluation report to src/models/saved/.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np

from src.models.ml_engine import (
    train_test_split,
    LogisticRegressionClassifier,
    RandomForestClassifier,
    GradientBoostingClassifier,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)


def train_and_evaluate():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    features_csv = os.path.join(base_dir, 'data', 'processed', 'features.csv')
    
    if not os.path.exists(features_csv):
        raise FileNotFoundError(f"Features dataset not found at {features_csv}. Run data/prepare_dataset.py first.")

    print(f"Loading features dataset from {features_csv}...")
    df = pd.read_csv(features_csv)
    
    feature_cols = [c for c in df.columns if c not in ['label', 'url']]
    X = df[feature_cols]
    y = df['label']

    print(f"Features ({len(feature_cols)}): {feature_cols}")
    print(f"Total dataset: {len(X)} samples. Distribution: {y.value_counts().to_dict()}")

    # Stratified 80/20 train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    models = {
        'Logistic Regression': LogisticRegressionClassifier(lr=0.08, n_iters=1000, l2_reg=0.01),
        'Random Forest': RandomForestClassifier(n_estimators=40, max_depth=8, max_features='sqrt', random_state=42),
        'Gradient Boosting': GradientBoostingClassifier(n_estimators=35, learning_rate=0.12, max_depth=5, random_state=42)
    }

    results = {}
    best_f1 = -1.0
    best_model_name = None
    champion_model = None

    print("\n--- Training and Evaluating Models ---")
    for name, model in models.items():
        print(f"Training {name} on {len(X_train)} samples...")
        model.fit(X_train, y_train)

        # Predictions
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, pos_label=1)
        rec = recall_score(y_test, y_pred, pos_label=1)
        f1 = f1_score(y_test, y_pred, pos_label=1)
        roc_auc = roc_auc_score(y_test, y_prob)
        cm = confusion_matrix(y_test, y_pred)

        results[name] = {
            'accuracy': round(acc, 4),
            'precision': round(prec, 4),
            'recall': round(rec, 4),
            'f1_score': round(f1, 4),
            'roc_auc': round(roc_auc, 4),
            'confusion_matrix': cm
        }

        print(f"[{name}] Acc: {acc*100:.2f}% | Prec: {prec*100:.2f}% | Recall: {rec*100:.2f}% | F1: {f1:.4f} | ROC-AUC: {roc_auc:.4f}")

        # Prioritize F1 and Recall
        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            champion_model = model

    print(f"\nChampion Model Selected: {best_model_name} (F1 = {best_f1:.4f})")

    # Save champion model & metadata
    saved_dir = os.path.join(base_dir, 'src', 'models', 'saved')
    os.makedirs(saved_dir, exist_ok=True)

    model_save_path = os.path.join(saved_dir, 'production_model.pkl')
    metadata = {
        'model_name': best_model_name,
        'feature_names': feature_cols,
        'metrics': results,
        'train_samples': len(X_train),
        'test_samples': len(X_test)
    }

    joblib.dump({
        'model': champion_model,
        'metadata': metadata
    }, model_save_path)
    print(f"Saved champion model to {model_save_path}")

    # Also save metrics.json for API consumption
    metrics_path = os.path.join(saved_dir, 'metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"Saved evaluation metrics to {metrics_path}")

    return metadata


if __name__ == '__main__':
    train_and_evaluate()
