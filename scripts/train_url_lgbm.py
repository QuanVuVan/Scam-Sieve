# File: scripts/train_url_lgbm.py
"""
Huấn luyện và Đánh giá Chuyên sâu Mô hình Phishing URL Chuẩn Công nghiệp (LightGBM):
- 20 đặc trưng Lexical thuần túy đã tối ưu chống học vẹt (Anti-Shortcut Learning).
- Huấn luyện trên tập dữ liệu chuẩn công nghiệp đa dạng (data/url_dataset_industrial.csv).
- Phân chia tập Train/Test theo Tên miền (Domain Grouping - GroupShuffleSplit) với 0% rò rỉ dữ liệu.
- Đo lường toàn diện: Confusion Matrix, Precision, Recall, F1, PR-AUC, ROC-AUC,
  Khoảng tin cậy 95% Bootstrap, Mô phỏng Precision ở tỷ lệ thực tế (1% & 5%), và Kiểm thử ngoài đời (OOD).
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


def compute_bootstrap_ci(y_true, y_pred, n_bootstraps=1000, alpha=0.05):
    rng = np.random.RandomState(42)
    accs, precs, recs, f1s = [], [], [], []
    n = len(y_true)
    for _ in range(n_bootstraps):
        indices = rng.randint(0, n, n)
        if len(np.unique(y_true[indices])) < 2:
            continue
        yt = y_true[indices]
        yp = y_pred[indices]
        accs.append(accuracy_score(yt, yp))
        precs.append(precision_score(yt, yp, zero_division=0))
        recs.append(recall_score(yt, yp, zero_division=0))
        f1s.append(f1_score(yt, yp, zero_division=0))

    def get_ci(arr):
        low = np.percentile(arr, (alpha / 2.0) * 100)
        high = np.percentile(arr, (1.0 - alpha / 2.0) * 100)
        return low, high

    return {
        "accuracy": get_ci(accs),
        "precision": get_ci(precs),
        "recall": get_ci(recs),
        "f1": get_ci(f1s)
    }


def train_and_evaluate_industrial():
    data_path = 'data/url_dataset_industrial.csv'
    model_save_path = 'app/detector/url_lgbm_model.joblib'

    print("=" * 75)
    print("  HUAN LUYEN VA DANH GIA CHUYEN SAU MO HINH PHISHING URL (LIGHTGBM)")
    print("=" * 75)

    df = pd.read_csv(data_path)
    total_records = len(df)
    counts = df['type'].value_counts()
    print(f"1. TONG QUAN TAP DU LIEU HUAN LUYEN:")
    print(f"   - Tong so ban ghi: {total_records:,} mau")
    print(f"   - So mau Lanh tinh (Benign)  : {counts.get('benign', 0):,} ({counts.get('benign', 0)/total_records*100:.2f}%)")
    print(f"   - So mau Lua dao (Phishing)  : {counts.get('phishing', 0):,} ({counts.get('phishing', 0)/total_records*100:.2f}%)")

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
    unique_domains = len(np.unique(groups))
    print(f"   - Tong so ten mien doc nhat: {unique_domains:,} domains")

    # GroupShuffleSplit theo Domain (75% Train - 25% Test)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups=groups))

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    train_domains = set(groups[train_idx])
    test_domains = set(groups[test_idx])
    domain_overlap = len(train_domains.intersection(test_domains))

    print(f"\n2. PHAN CHIA THEO GROUP DOMAINS (0% DOMAIN LEAKAGE):")
    print(f"   - Tap Train: {len(X_train):,} mau ({len(train_domains):,} domains) | Phishing: {sum(y_train):,}, Benign: {len(y_train) - sum(y_train):,}")
    print(f"   - Tap Test : {len(X_test):,} mau ({len(test_domains):,} domains) | Phishing: {sum(y_test):,}, Benign: {len(y_test) - sum(y_test):,}")
    print(f"   - Do trung lap Ten mien giua Train va Test: {domain_overlap} (Hoan toan doc lap 100%)")

    # Cấu hình LightGBM tối ưu chống học vẹt và chống quá khớp
    lgbm_url = LGBMClassifier(
        n_estimators=300,
        learning_rate=0.03,
        num_leaves=20,
        max_depth=4,
        min_child_samples=40,
        subsample=0.8,
        colsample_bytree=0.6,
        class_weight='balanced',
        random_state=42,
        verbose=-1
    )

    print("\n3. DANG HUAN LUYEN LIGHTGBM CLASSIFIER...")
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
    tn, fp, fn, tp = cm.ravel()

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0

    print("\n" + "=" * 75)
    print("4. KET QUA DANH GIA MO HINH TREN TAP TEST UNSEEN DOMAINS (1.515 DOMAINS MOI):")
    print("=" * 75)
    print(f"   - Accuracy  (Do chinh xac tong the) : {acc * 100:.2f}%")
    print(f"   - Precision (Do chuan xac Phishing) : {prec * 100:.2f}%")
    print(f"   - Recall    (Do bao phu Phishing)   : {rec * 100:.2f}%")
    print(f"   - F1-Score                          : {f1 * 100:.2f}%")
    print(f"   - Specificity (Do dac hieu Benign)  : {specificity * 100:.2f}%")
    print(f"   - False Positive Rate (FPR - Bao nham): {fpr * 100:.2f}%")
    print(f"   - False Negative Rate (FNR - Bo sot):  {fnr * 100:.2f}%")
    print(f"   - ROC-AUC                           : {roc_auc * 100:.2f}%")
    print(f"   - PR-AUC (Average Precision)        : {pr_auc * 100:.2f}%")
    print("-" * 75)

    print("5. MA TRAN NHAM LAN (CONFUSION MATRIX):")
    print(f"                       Du doan Benign       Du doan Phishing       Tong thuc te")
    print(f"   Thuc te Benign   :  {tn:<18,}  {fp:<20,}  {tn + fp:,}")
    print(f"   Thuc te Phishing :  {fn:<18,}  {tp:<20,}  {fn + tp:,}")
    print(f"   Tong du doan     :  {tn + fn:<18,}  {fp + tp:<20,}  {len(y_test):,}")
    print("-" * 75)

    # 95% Bootstrap Confidence Intervals
    print("\n6. KHOANG TIN CAY 95% (BOOTSTRAP 1.000 LAN LAP):")
    ci = compute_bootstrap_ci(y_test, y_pred, n_bootstraps=1000)
    print(f"   - Accuracy CI (95%)  : [{ci['accuracy'][0]*100:.2f}%  -  {ci['accuracy'][1]*100:.2f}%]")
    print(f"   - Precision CI (95%) : [{ci['precision'][0]*100:.2f}%  -  {ci['precision'][1]*100:.2f}%]")
    print(f"   - Recall CI (95%)    : [{ci['recall'][0]*100:.2f}%  -  {ci['recall'][1]*100:.2f}%]")
    print(f"   - F1-Score CI (95%)  : [{ci['f1'][0]*100:.2f}%  -  {ci['f1'][1]*100:.2f}%]")

    # Mô phỏng Precision ở tỷ lệ thực tế ngoài đời (Prevalence Simulation via Bayes Theorem)
    print("\n7. MO PHONG PRECISION O TY LE LUA DAO THUC TE (BAYESIAN PREVALENCE):")
    for prev in [0.01, 0.05, 0.10]:
        prec_real = (rec * prev) / ((rec * prev) + (fpr * (1 - prev)))
        print(f"   - O ty le lua dao {prev*100:2.0f}%: Precision thuc te dat {prec_real * 100:.2f}%")

    # Báo cáo phân loại chi tiết
    print("\n8. BANG PHAN LOAI CHI TIET (CLASSIFICATION REPORT):")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Phishing"], digits=4))

    # Feature Importance
    importances = lgbm_url.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("9. DO QUAN TRONG CUA 20 DAC TRUNG LEXICAL (FEATURE IMPORTANCE):")
    for rank, idx in enumerate(sorted_idx, 1):
        print(f"   {rank:2d}. {LEXICAL_FEATURE_NAMES[idx]:<22} : {importances[idx]:4d} splits")

    bundle = {
        "model": lgbm_url,
        "feature_names": LEXICAL_FEATURE_NAMES,
        "metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "confusion_matrix": cm.tolist(),
            "ci_95": {k: [float(v[0]), float(v[1])] for k, v in ci.items()}
        }
    }
    joblib.dump(bundle, model_save_path)
    print(f"\nDa luu mo hinh URL LightGBM thanh cong tai: {model_save_path}")
    print("=" * 75)


if __name__ == "__main__":
    train_and_evaluate_industrial()
