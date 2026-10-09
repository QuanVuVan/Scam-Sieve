import csv
import logging
from typing import List, Dict
from sklearn.metrics import confusion_matrix, precision_score, recall_score, accuracy_score
import sys
import os

# Đảm bảo import được module từ app/
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.detector.scorer import RiskScorer

# Cấu hình Logging để in ra console
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DetectorEvaluator:
    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path
        self.scorer = RiskScorer()
        
    def load_data(self) -> tuple[List[str], List[int]]:
        """Tải dữ liệu từ CSV. Giả định cấu trúc: text, label (1 là scam, 0 là safe)"""
        texts = []
        labels = []
        try:
            with open(self.dataset_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    texts.append(row['text'])
                    labels.append(int(row['label']))
            return texts, labels
        except Exception as e:
            logger.error(f"Failed to load dataset: {str(e)}")
            return [], []

    def run_evaluation(self):
        texts, true_labels = self.load_data()
        if not texts:
            return

        pred_labels = []
        false_positives = []
        false_negatives = []

        logger.info(f"Đang đánh giá {len(texts)} mẫu dữ liệu...")

        for i, text in enumerate(texts):
            # Gọi pipeline phân tích
            result = self.scorer.analyze_message(text)
            pred_label = 1 if result["is_scam"] else 0
            pred_labels.append(pred_label)

            # Thu thập các ca dự đoán sai để phân tích nguyên nhân gốc rễ (Root Cause Analysis)
            true_label = true_labels[i]
            if true_label == 0 and pred_label == 1:
                false_positives.append((text, result))
            elif true_label == 1 and pred_label == 0:
                false_negatives.append((text, result))

        # Tính toán các chỉ số (Metrics)
        acc = accuracy_score(true_labels, pred_labels)
        precision = precision_score(true_labels, pred_labels, zero_division=0)
        recall = recall_score(true_labels, pred_labels, zero_division=0)
        tn, fp, fn, tp = confusion_matrix(true_labels, pred_labels).ravel()

        self._print_report(acc, precision, recall, tn, fp, fn, tp)
        self._analyze_errors(false_positives, "FALSE POSITIVES (Chan nham oan)")
        self._analyze_errors(false_negatives, "FALSE NEGATIVES (Bo lot lua dao)")

    def _print_report(self, acc, precision, recall, tn, fp, fn, tp):
        lines = [
            "\n" + "="*50,
            "BAO CAO HIEU NANG PHAN TICH (ACCURACY & PRECISION REPORT)",
            "="*50,
            f"Accuracy (Do chinh xac tong the) : {acc:.4f} ({acc*100:.2f}%)",
            f"Precision (Do tin cay)           : {precision:.4f} ({precision*100:.2f}%)",
            f"Recall (Do phu bat scam)         : {recall:.4f} ({recall*100:.2f}%)",
            "-" * 50,
            f"True Negatives (TN - An toan chuan)  : {tn}",
            f"True Positives (TP - Bat trung Scam) : {tp}",
            f"False Positives(FP - CHAN NHAM OAN)  : {fp} (Muc tieu: 0)",
            f"False Negatives(FN - Bo lot Scam)    : {fn}",
            "="*50,
        ]
        for line in lines:
            print(line)

    def _analyze_errors(self, error_list, title):
        if not error_list:
            return
        print(f"\n[PHAN TICH] {title}")
        for i, (text, result) in enumerate(error_list[:5]):
            safe_text = text.encode('ascii', 'ignore').decode()[:80]
            print(f"\nMau {i+1}: {safe_text}")
            print(f"   -> Diem rui ro: {result['risk_score']}")
            safe_reason = str(result['reason']).encode('ascii', 'ignore').decode()[:100]
            print(f"   -> Ly do kich hoat: {safe_reason}")

if __name__ == "__main__":
    dataset = "data/labeled_messages.csv"
    evaluator = DetectorEvaluator(dataset)
    evaluator.run_evaluation()