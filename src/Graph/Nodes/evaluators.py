from sklearn.metrics import precision_score, recall_score, f1_score

def compute_individual_scores(y_true, y_pred, all_labels):
    """
    Compute per-CVE precision, recall, F1
    y_true, y_pred: list of strings (labels)
    all_labels: list of all possible labels in dataset
    """
    labels_list = list(all_labels)

    y_true_bin = [1 if l in y_true else 0 for l in labels_list]
    y_pred_bin = [1 if l in y_pred else 0 for l in labels_list]

    y_true_arr = [y_true_bin]
    y_pred_arr = [y_pred_bin]

    scores = {
        "precision": float(precision_score(y_true_arr, y_pred_arr, average="micro", zero_division=0)),
        "recall": float(recall_score(y_true_arr, y_pred_arr, average="micro", zero_division=0)),
        "f1": float(f1_score(y_true_arr, y_pred_arr, average="micro", zero_division=0)),
    }
    return scores

def compute_grouped_scores(all_y_true, all_y_pred, all_labels):
    """
    Compute global precision, recall, F1 across all CVEs in the run.
    """
    labels_list = list(all_labels)
    
    # Binarize all samples in the batch
    y_true_matrix = [[1 if l in y_true else 0 for l in labels_list] for y_true in all_y_true]
    y_pred_matrix = [[1 if l in y_pred else 0 for l in labels_list] for y_pred in all_y_pred]
    
    scores = {
        "precision": float(precision_score(y_true_matrix, y_pred_matrix, average="micro", zero_division=0)),
        "recall": float(recall_score(y_true_matrix, y_pred_matrix, average="micro", zero_division=0)),
        "f1": float(f1_score(y_true_matrix, y_pred_matrix, average="micro", zero_division=0)),
    }
    return scores
