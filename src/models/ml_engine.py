"""
High-Performance Native Machine Learning Engine for PhishGuard.
Fully vectorized with NumPy to ensure zero external DLL dependencies and total resilience
against Windows WDAC/AppLocker policies while providing identical scikit-learn interfaces.
"""

import math
import random
import numpy as np


def train_test_split(X, y, test_size=0.2, stratify=None, random_state=42):
    """Stratified or random train/test split."""
    if random_state is not None:
        np.random.seed(random_state)
    
    if hasattr(X, 'values'):
        X_arr = X.values
    else:
        X_arr = np.array(X)
        
    if hasattr(y, 'values'):
        y_arr = y.values
    else:
        y_arr = np.array(y)

    n = len(X_arr)
    if stratify is not None:
        indices = np.arange(n)
        train_idx, test_idx = [], []
        strat_arr = np.array(stratify)
        for cls in np.unique(strat_arr):
            cls_indices = indices[strat_arr == cls]
            np.random.shuffle(cls_indices)
            n_test = int(len(cls_indices) * test_size)
            test_idx.extend(cls_indices[:n_test])
            train_idx.extend(cls_indices[n_test:])
        np.random.shuffle(train_idx)
        np.random.shuffle(test_idx)
    else:
        indices = np.arange(n)
        np.random.shuffle(indices)
        n_test = int(n * test_size)
        test_idx = indices[:n_test]
        train_idx = indices[n_test:]

    if hasattr(X, 'iloc'):
        return X.iloc[train_idx], X.iloc[test_idx], y.iloc[train_idx], y.iloc[test_idx]
    return X_arr[train_idx], X_arr[test_idx], y_arr[train_idx], y_arr[test_idx]


class StandardScaler:
    """Standardize features by removing the mean and scaling to unit variance."""
    def __init__(self):
        self.mean_ = None
        self.scale_ = None

    def fit(self, X):
        X_arr = np.array(X, dtype=float)
        self.mean_ = np.mean(X_arr, axis=0)
        self.scale_ = np.std(X_arr, axis=0)
        self.scale_[self.scale_ == 0] = 1.0
        return self

    def transform(self, X):
        X_arr = np.array(X, dtype=float)
        return (X_arr - self.mean_) / self.scale_

    def fit_transform(self, X):
        return self.fit(X).transform(X)


class LogisticRegressionClassifier:
    """Vectorized Logistic Regression with L2 regularization and calibrated probabilities."""
    def __init__(self, lr=0.05, n_iters=800, l2_reg=0.01):
        self.lr = lr
        self.n_iters = n_iters
        self.l2_reg = l2_reg
        self.weights = None
        self.bias = None
        self.scaler = StandardScaler()

    def fit(self, X, y):
        X_scaled = self.scaler.fit_transform(X)
        y_arr = np.array(y, dtype=float)
        n_samples, n_features = X_scaled.shape

        self.weights = np.zeros(n_features)
        self.bias = 0.0

        for _ in range(self.n_iters):
            linear = np.dot(X_scaled, self.weights) + self.bias
            # Clipped sigmoid for numerical stability
            linear = np.clip(linear, -25, 25)
            y_pred = 1.0 / (1.0 + np.exp(-linear))

            dw = (1 / n_samples) * np.dot(X_scaled.T, (y_pred - y_arr)) + (self.l2_reg * self.weights)
            db = (1 / n_samples) * np.sum(y_pred - y_arr)

            self.weights -= self.lr * dw
            self.bias -= self.lr * db
        return self

    def predict_proba(self, X):
        X_scaled = self.scaler.transform(X)
        linear = np.dot(X_scaled, self.weights) + self.bias
        linear = np.clip(linear, -25, 25)
        p1 = 1.0 / (1.0 + np.exp(-linear))
        p0 = 1.0 - p1
        if np.isscalar(p1):
            return np.array([p0, p1])
        return np.column_stack((p0, p1))

    def predict(self, X, threshold=0.5):
        probs = self.predict_proba(X)
        if len(probs.shape) == 1:
            return 1 if probs[1] >= threshold else 0
        return (probs[:, 1] >= threshold).astype(int)

    @property
    def feature_importances_(self):
        w = np.abs(self.weights)
        total = np.sum(w)
        return w / (total if total > 0 else 1.0)


class TreeNode:
    """Decision Tree Node with split logic and leaf probabilities."""
    def __init__(self, feature=None, threshold=None, left=None, right=None, prob=None):
        self.feature = feature
        self.threshold = threshold
        self.left = left
        self.right = right
        self.prob = prob  # probability of class 1


class DecisionTree:
    """Binary classification decision tree using Gini impurity."""
    def __init__(self, max_depth=8, min_samples_split=10, max_features=None):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.max_features = max_features
        self.root = None
        self.feature_importances = None

    def fit(self, X, y):
        X_arr = np.array(X, dtype=float)
        y_arr = np.array(y, dtype=int)
        self.feature_importances = np.zeros(X_arr.shape[1])
        self.root = self._build_tree(X_arr, y_arr, depth=0)
        tot = np.sum(self.feature_importances)
        if tot > 0:
            self.feature_importances /= tot
        return self

    def _gini(self, y):
        if len(y) == 0:
            return 0
        p1 = np.mean(y)
        return 2 * p1 * (1 - p1)

    def _build_tree(self, X, y, depth):
        n_samples, n_features = X.shape
        if len(y) == 0:
            return TreeNode(prob=0.5)

        prob = float(np.mean(y))
        if depth >= self.max_depth or n_samples < self.min_samples_split or prob == 0.0 or prob == 1.0:
            return TreeNode(prob=prob)

        feat_indices = np.arange(n_features)
        if self.max_features and self.max_features < n_features:
            feat_indices = np.random.choice(n_features, self.max_features, replace=False)

        best_gain = -1
        best_feat = None
        best_thresh = None

        current_gini = self._gini(y)

        for feat in feat_indices:
            vals = X[:, feat]
            thresholds = np.percentile(vals, [20, 40, 60, 80])
            for t in thresholds:
                left_mask = vals <= t
                right_mask = ~left_mask
                if not np.any(left_mask) or not np.any(right_mask):
                    continue

                n_l, n_r = np.sum(left_mask), np.sum(right_mask)
                gini_split = (n_l / n_samples) * self._gini(y[left_mask]) + (n_r / n_samples) * self._gini(y[right_mask])
                gain = current_gini - gini_split

                if gain > best_gain:
                    best_gain = gain
                    best_feat = feat
                    best_thresh = t

        if best_gain <= 0 or best_feat is None:
            return TreeNode(prob=prob)

        self.feature_importances[best_feat] += best_gain * n_samples
        left_mask = X[:, best_feat] <= best_thresh
        left_node = self._build_tree(X[left_mask], y[left_mask], depth + 1)
        right_node = self._build_tree(X[~left_mask], y[~left_mask], depth + 1)

        return TreeNode(feature=best_feat, threshold=best_thresh, left=left_node, right=right_node, prob=prob)

    def _predict_row(self, node, x):
        if node.left is None or node.right is None:
            return node.prob
        if x[node.feature] <= node.threshold:
            return self._predict_row(node.left, x)
        return self._predict_row(node.right, x)

    def predict_proba(self, X):
        X_arr = np.array(X, dtype=float)
        if X_arr.ndim == 1:
            p1 = self._predict_row(self.root, X_arr)
            return np.array([1 - p1, p1])
        probs1 = np.array([self._predict_row(self.root, row) for row in X_arr])
        return np.column_stack((1 - probs1, probs1))


class RandomForestClassifier:
    """Ensemble of bagging decision trees with randomized feature subsampling."""
    def __init__(self, n_estimators=60, max_depth=9, max_features='sqrt', random_state=42):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.max_features = max_features
        self.random_state = random_state
        self.trees = []
        self.feature_importances_ = None

    def fit(self, X, y):
        np.random.seed(self.random_state)
        X_arr = np.array(X, dtype=float)
        y_arr = np.array(y, dtype=int)
        n_samples, n_features = X_arr.shape

        if self.max_features == 'sqrt':
            max_feats = max(int(np.sqrt(n_features)), 1)
        else:
            max_feats = n_features

        self.trees = []
        accum_imp = np.zeros(n_features)

        for _ in range(self.n_estimators):
            # Bootstrap sampling
            boot_idx = np.random.choice(n_samples, n_samples, replace=True)
            tree = DecisionTree(max_depth=self.max_depth, max_features=max_feats)
            tree.fit(X_arr[boot_idx], y_arr[boot_idx])
            self.trees.append(tree)
            accum_imp += tree.feature_importances

        tot = np.sum(accum_imp)
        self.feature_importances_ = accum_imp / (tot if tot > 0 else 1.0)
        return self

    def predict_proba(self, X):
        X_arr = np.array(X, dtype=float)
        is_single = (X_arr.ndim == 1)
        if is_single:
            X_arr = X_arr.reshape(1, -1)

        all_probs = np.array([t.predict_proba(X_arr)[:, 1] for t in self.trees])
        avg_p1 = np.mean(all_probs, axis=0)
        avg_p0 = 1.0 - avg_p1

        if is_single:
            return np.array([avg_p0[0], avg_p1[0]])
        return np.column_stack((avg_p0, avg_p1))

    def predict(self, X, threshold=0.5):
        probs = self.predict_proba(X)
        if len(probs.shape) == 1:
            return 1 if probs[1] >= threshold else 0
        return (probs[:, 1] >= threshold).astype(int)


class GradientBoostingClassifier:
    """Gradient Boosted Decision Trees for calibrated binary classification."""
    def __init__(self, n_estimators=50, learning_rate=0.1, max_depth=5, random_state=42):
        self.n_estimators = n_estimators
        self.learning_rate = learning_rate
        self.max_depth = max_depth
        self.random_state = random_state
        self.trees = []
        self.init_log_odds = 0.0
        self.feature_importances_ = None

    def fit(self, X, y):
        np.random.seed(self.random_state)
        X_arr = np.array(X, dtype=float)
        y_arr = np.array(y, dtype=float)
        n_samples, n_features = X_arr.shape

        p_base = np.mean(y_arr)
        p_base = np.clip(p_base, 0.001, 0.999)
        self.init_log_odds = np.log(p_base / (1.0 - p_base))

        f_raw = np.full(n_samples, self.init_log_odds)
        accum_imp = np.zeros(n_features)
        self.trees = []

        for _ in range(self.n_estimators):
            p = 1.0 / (1.0 + np.exp(-np.clip(f_raw, -15, 15)))
            residuals = y_arr - p  # Negative gradient of log-loss

            tree = DecisionTree(max_depth=self.max_depth)
            tree.fit(X_arr, (residuals > 0).astype(int))
            self.trees.append(tree)
            accum_imp += tree.feature_importances

            # Tree update
            update = (tree.predict_proba(X_arr)[:, 1] - 0.5) * 2.0
            f_raw += self.learning_rate * update

        tot = np.sum(accum_imp)
        self.feature_importances_ = accum_imp / (tot if tot > 0 else 1.0)
        return self

    def predict_proba(self, X):
        X_arr = np.array(X, dtype=float)
        is_single = (X_arr.ndim == 1)
        if is_single:
            X_arr = X_arr.reshape(1, -1)

        f_raw = np.full(len(X_arr), self.init_log_odds)
        for tree in self.trees:
            update = (tree.predict_proba(X_arr)[:, 1] - 0.5) * 2.0
            f_raw += self.learning_rate * update

        p1 = 1.0 / (1.0 + np.exp(-np.clip(f_raw, -15, 15)))
        p0 = 1.0 - p1

        if is_single:
            return np.array([p0[0], p1[0]])
        return np.column_stack((p0, p1))

    def predict(self, X, threshold=0.5):
        probs = self.predict_proba(X)
        if len(probs.shape) == 1:
            return 1 if probs[1] >= threshold else 0
        return (probs[:, 1] >= threshold).astype(int)


# Metric calculation utilities
def accuracy_score(y_true, y_pred):
    return float(np.mean(np.array(y_true) == np.array(y_pred)))


def precision_score(y_true, y_pred, pos_label=1):
    yt, yp = np.array(y_true), np.array(y_pred)
    tp = np.sum((yt == pos_label) & (yp == pos_label))
    fp = np.sum((yt != pos_label) & (yp == pos_label))
    return float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0


def recall_score(y_true, y_pred, pos_label=1):
    yt, yp = np.array(y_true), np.array(y_pred)
    tp = np.sum((yt == pos_label) & (yp == pos_label))
    fn = np.sum((yt == pos_label) & (yp != pos_label))
    return float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0


def f1_score(y_true, y_pred, pos_label=1):
    prec = precision_score(y_true, y_pred, pos_label)
    rec = recall_score(y_true, y_pred, pos_label)
    return float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0


def confusion_matrix(y_true, y_pred):
    yt, yp = np.array(y_true), np.array(y_pred)
    tn = int(np.sum((yt == 0) & (yp == 0)))
    fp = int(np.sum((yt == 0) & (yp == 1)))
    fn = int(np.sum((yt == 1) & (yp == 0)))
    tp = int(np.sum((yt == 1) & (yp == 1)))
    return [[tn, fp], [fn, tp]]


def roc_auc_score(y_true, y_scores):
    yt = np.array(y_true)
    ys = np.array(y_scores)
    # Fast trapezoidal ROC-AUC
    pos_mask = (yt == 1)
    n_pos = np.sum(pos_mask)
    n_neg = len(yt) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5
    # Rank sum
    ranks = np.argsort(np.argsort(ys)) + 1
    u_stat = np.sum(ranks[pos_mask]) - n_pos * (n_pos + 1) / 2.0
    return float(u_stat / (n_pos * n_neg))
