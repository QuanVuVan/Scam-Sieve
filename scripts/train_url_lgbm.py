# File: scripts/train_url_lgbm.py
"""
Huấn luyện mô hình Phishing URL Chuẩn Công nghiệp (LightGBM):
- Sử dụng 20 đặc trưng Lexical thuần túy đã tối ưu chống học vẹt (Anti-Shortcut Learning).
- Huấn luyện trên tập dữ liệu đa dạng (data/url_dataset_industrial.csv).
- Đánh giá bằng GroupSplit theo Tên miền (Domain Grouping) để kiểm tra năng lực tổng quát hóa
  trên các tên miền hoàn toàn mới (0% rò rỉ dữ liệu / zero domain overlap).
"""
import os
import sys
import joblib
from urllib.parse import urlparse

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    average_precision_score
)
from lightgbm import LGBMClassifier

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.detector.url_ml_classifier import extract_20_lexical_features, LEXICAL_FEATURE_NAMES


def get_domain(url_str: str) -> str:
    try:
        u = str(url_str or "").strip()
        parsed = urlparse(u if "://" in u else f"http://{u}")
        netloc = parsed.netloc.lower()
        if ':' in netloc:
            netloc = netloc.split(':')[0]
        return netloc or "unknown_domain"
    except Exception:
        return "unknown_domain"


def train_and_evaluate_industrial():
    data_path = 'data/url_dataset_industrial.csv'
    model_save_path = 'app/detector/url_lgbm_model.joblib'

    print("=" * 65)
    print("HUAN LUYEN MO HINH PHISHING URL ANTI-SHORTCUT (20 LEXICAL FEATURES)")
    print("=" * 65)

    df = pd.read_csv(data_path)
    print(f"Tổng số bản ghi tập dữ liệu: {len(df)}")
    print(f"Phân bố nhãn:\n{df['type'].value_counts()}\n")

    X = []
    y = []
    groups = []

    for idx, row in df.iterrows():
        url = str(row.get('url', '')).strip()
        feats = extract_20_lexical_features(url)
        X.append(feats)
        label = 1 if str(row.get('type', '')).lower().strip() == 'phishing' else 0
        y.append(label)
        groups.append(get_domain(url))

    X = np.array(X)
    y = np.array(y)
    groups = np.array(groups)

    print(f"Tổng số tên miền độc nhất (Unique Domains): {len(np.unique(groups))}")

    # Chia Train / Test theo Domain (GroupShuffleSplit 75% Train - 25% Test)
    # Đảm bảo 100% không trùng lặp domain giữa train và test
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups=groups))

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    train_domains = set(groups[train_idx])
    test_domains = set(groups[test_idx])
    domain_overlap = len(train_domains.intersection(test_domains))

    print(f"Tap Train: {len(X_train)} mau tu {len(train_domains)} domains (Phishing: {sum(y_train)}, Benign: {len(y_train) - sum(y_train)})")
    print(f"Tap Test : {len(X_test)} mau tu {len(test_domains)} domains (Phishing: {sum(y_test)}, Benign: {len(y_test) - sum(y_test)})")
    print(f"Domain Overlap giua Train va Test: {domain_overlap} (Hoan toan doc lap 100%)\n")

    # Cấu hình LightGBM tối ưu chống học vẹt và chống quá khớp (Anti-Overfitting & Regularization)
    lgbm_url = LGBMClassifier(
        n_estimators=300,
        learning_rate=0.03,
        num_leaves=20,
        max_depth=4,               # Cây nông giúp tổng quát hóa tốt hơn, tránh học vẹt
        min_child_samples=40,      # Ngăn các node lá tách theo số ít mẫu cá biệt
        subsample=0.8,
        colsample_bytree=0.6,      # Lấy ngẫu nhiên 60% đặc trưng mỗi cây để loại bỏ phụ thuộc một chiều
        class_weight='balanced',
        random_state=42,
        verbose=-1
    )

    print("Dang huan luyen LightGBM Classifier tren tap Train...")
    lgbm_url.fit(X_train, y_train)

    y_pred = lgbm_url.predict(X_test)
    y_prob = lgbm_url.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_prob)
    pr_auc = average_precision_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 65)
    print("KET QUA DANH GIA MO HINH TREN TAP TEST UNSEEN DOMAINS (GROUP SPLIT):")
    print("=" * 65)
    print(f"- Accuracy  (Do chinh xac tong the):  {acc * 100:.2f}%")
    print(f"- Precision (Do chuan xac Phishing): {prec * 100:.2f}%")
    print(f"- Recall    (Do bao phu Phishing):    {rec * 100:.2f}%")
    print(f"- F1-Score:                          {f1 * 100:.2f}%")
    print(f"- ROC-AUC:                           {roc_auc * 100:.2f}%")
    print(f"- PR-AUC:                            {pr_auc * 100:.2f}%")
    print("-" * 65)
    print("Ma tran nham lan (Confusion Matrix):\n")
    print(f"              Du doan Benign  |  Du doan Phishing")
    print(f"Thuc te Benign:    {cm[0][0]:<10} |  {cm[0][1]:<10}")
    print(f"Thuc te Phishing:  {cm[1][0]:<10} |  {cm[1][1]:<10}")
    print("-" * 65)
    print("\nBao cao phan loai chi tiet (Classification Report):")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Phishing"], digits=4))

    # Đánh giá Feature Importance
    importances = lgbm_url.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("\nDo quan trong cua 20 Dac trung Lexical:")
    for rank, idx in enumerate(sorted_idx, 1):
        print(f"  {rank:2d}. {LEXICAL_FEATURE_NAMES[idx]:<22} : {importances[idx]}")

    bundle = {
        "model": lgbm_url,
        "feature_names": LEXICAL_FEATURE_NAMES,
        "metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc
        }
    }
    joblib.dump(bundle, model_save_path)
    print(f"\nDa luu mo hinh URL LightGBM thanh cong tai: {model_save_path}")
    print("=" * 65)


if __name__ == "__main__":
    train_and_evaluate_industrial()
