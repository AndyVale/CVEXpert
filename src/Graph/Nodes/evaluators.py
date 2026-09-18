from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

def compute_individual_scores(y_true, y_pred, all_labels):
    """
    Compute per-CVE exact-match accuracy, precision, recall, F1
    y_true, y_pred: list of strings (labels)
    all_labels: list of all possible labels in dataset
    """
    # Remove unknown labels
    y_pred_clean = [l for l in y_pred if l in all_labels]

    mlb = MultiLabelBinarizer(classes=all_labels)
    y_true_bin = mlb.fit_transform([y_true])
    y_pred_bin = mlb.transform([y_pred_clean])

    scores = {
        "accuracy": float(accuracy_score(y_true_bin, y_pred_bin)),
        "precision": float(precision_score(y_true_bin, y_pred_bin, average="micro", zero_division=0)),
        "recall": float(recall_score(y_true_bin, y_pred_bin, average="micro", zero_division=0)),
        "f1": float(f1_score(y_true_bin, y_pred_bin, average="micro", zero_division=0)),
    }
    return scores


def compute_grouped_scores(all_y_true, all_y_pred, all_labels):
    """
    Compute exact-match accuracy and micro metrics over the selected CVEs
    all_y_true, all_y_pred: lists of lists of strings
    """
    mlb = MultiLabelBinarizer(classes=all_labels)
    y_true_bin = mlb.fit_transform(all_y_true)
    y_pred_bin = mlb.transform(all_y_pred)

    scores = {
        "accuracy": float(accuracy_score(y_true_bin, y_pred_bin)),
        "precision": float(precision_score(y_true_bin, y_pred_bin, average="micro", zero_division=0)),
        "recall": float(recall_score(y_true_bin, y_pred_bin, average="micro", zero_division=0)),
        "f1": float(f1_score(y_true_bin, y_pred_bin, average="micro", zero_division=0)),
    }
    return scores
