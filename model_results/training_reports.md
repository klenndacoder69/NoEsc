# NoEsc Training Reports

### results_negctrl_benign_vs_benign_min3.txt

```text
========================================================================
NoEsc Offline Training Report
========================================================================
Total sequence samples : 82664
Train samples (70%)    : 57864
Test samples (30%)     : 24800
Train class counts     : {0: np.int64(28932), 1: np.int64(28932)}
Test class counts      : {0: np.int64(12400), 1: np.int64(12400)}
------------------------------------------------------------------------
Accuracy               : 0.500000
Precision              : 0.500000
Recall                 : 0.588306
F1-Score               : 0.540571
False Positive Rate    : 0.588306
Matthews Corrcoef      : 0.000000
------------------------------------------------------------------------
Confusion Matrix (labels: 0=benign, 1=malicious): TN=5105 FP=7295 FN=5105 TP=7295
========================================================================
Saved SVM model      : models/negctrl_benign_vs_benign/svm_model.pkl
Saved TF-IDF vect.   : models/negctrl_benign_vs_benign/tfidf_vectorizer.pkl
Saved training meta  : models/negctrl_benign_vs_benign/training_metadata.json

```

### results_short_v1_min1.txt

```text
========================================================================
NoEsc Offline Training Report
========================================================================
Total sequence samples : 29433
Train samples (70%)    : 20602
Test samples (30%)     : 8831
Train class counts     : {0: np.int64(10497), 1: np.int64(10105)}
Test class counts      : {0: np.int64(4499), 1: np.int64(4332)}
------------------------------------------------------------------------
Accuracy               : 0.821311
Precision              : 0.959920
Recall                 : 0.663435
F1-Score               : 0.784603
False Positive Rate    : 0.026673
Matthews Corrcoef      : 0.672448
------------------------------------------------------------------------
Confusion Matrix (labels: 0=benign, 1=malicious): TN=4379 FP=120 FN=1458 TP=2874
========================================================================
Saved SVM model      : models/short_v1/svm_model.pkl
Saved TF-IDF vect.   : models/short_v1/tfidf_vectorizer.pkl
Saved training meta  : models/short_v1/training_metadata.json

```

### results_v1_min2.txt

```text
========================================================================
NoEsc Offline Training Report — Model: v1 (min_events=2)
========================================================================
Dataset Source          : sample_set/ml_inputs/ (old dataset)
Feature Contract        : v1 (SYSCALL-only context, no USER_AUTH)
========================================================================
Total sequence samples : 252495
Train samples (70%)    : 176746
Test samples (30%)     : 75749
Train class counts     : {0: 33424, 1: 143322}
Test class counts      : {0: 14325, 1: 61424}
------------------------------------------------------------------------
Accuracy               : 0.968026
Precision              : 0.970615
Recall                 : 0.990557
F1-Score               : 0.980485
False Positive Rate    : 0.128586
Matthews Corrcoef      : 0.893516
------------------------------------------------------------------------
Confusion Matrix (labels: 0=benign, 1=malicious): TN=12483 FP=1842 FN=580 TP=60844
========================================================================
Saved SVM model      : models/svm_model.pkl (later moved to models/v1/)
Saved TF-IDF vect.   : models/tfidf_vectorizer.pkl
Saved training meta  : models/training_metadata.json

```

### results_v3_min3.txt

```text
========================================================================
NoEsc Offline Training Report — Model: v3 (min_events=3)
========================================================================
Dataset Source          : sample_set/ml_inputs/ (old dataset)
Feature Contract        : v1 (SYSCALL-only context, no USER_AUTH)
========================================================================
Total sequence samples : 76978
Train samples (70%)    : 53884
Test samples (30%)     : 23094
Train class counts     : {0: 28932, 1: 24952}
Test class counts      : {0: 12400, 1: 10694}
------------------------------------------------------------------------
Accuracy               : 0.951849
Precision              : 0.905811
Recall                 : 1.000000
F1-Score               : 0.950578
False Positive Rate    : 0.089677
Matthews Corrcoef      : 0.908064
------------------------------------------------------------------------
Confusion Matrix (labels: 0=benign, 1=malicious): TN=11288 FP=1112 FN=0 TP=10694
========================================================================
Saved SVM model      : models/svm_model.pkl (later moved to models/v3/)
Saved TF-IDF vect.   : models/tfidf_vectorizer.pkl
Saved training meta  : models/training_metadata.json

```

### results_v4_min2.txt

```text
========================================================================
NoEsc Offline Training Report — Model: v4 (min_events=2)
========================================================================
Dataset Source          : sample_set/training_data/ (expanded dataset)
Feature Contract        : v2_syscall_user_auth_context
========================================================================
Total sequence samples : 367028
Train samples (70%)    : 256919
Test samples (30%)     : 110109
Train class counts     : {0: 33424, 1: 223495}
Test class counts      : {0: 14325, 1: 95784}
------------------------------------------------------------------------
Accuracy               : 0.794967
Precision              : 0.999277
Recall                 : 0.764856
F1-Score               : 0.866492
False Positive Rate    : 0.003700
Matthews Corrcoef      : 0.542850
------------------------------------------------------------------------
Confusion Matrix (labels: 0=benign, 1=malicious): TN=14272 FP=53 FN=22523 TP=73261
========================================================================
Saved SVM model      : models/v4/svm_model.pkl
Saved TF-IDF vect.   : models/v4/tfidf_vectorizer.pkl
Saved training meta  : models/v4/training_metadata.json

Note: This model was later overwritten by the v4 min_events=3 run.
The v4 directory currently contains the min3 model (identical to v4_min3 and v4_repro).

```

### results_v4_min3.txt

```text
========================================================================
NoEsc Offline Training Report
========================================================================
Total sequence samples : 123082
Train samples (70%)    : 86157
Test samples (30%)     : 36925
Train class counts     : {0: np.int64(28932), 1: np.int64(57225)}
Test class counts      : {0: np.int64(12400), 1: np.int64(24525)}
------------------------------------------------------------------------
Accuracy               : 0.997698
Precision              : 0.997963
Recall                 : 0.998573
F1-Score               : 0.998268
False Positive Rate    : 0.004032
Matthews Corrcoef      : 0.994839
------------------------------------------------------------------------
Confusion Matrix (labels: 0=benign, 1=malicious): TN=12350 FP=50 FN=35 TP=24490
========================================================================
Saved SVM model      : models/v4_repro/svm_model.pkl
Saved TF-IDF vect.   : models/v4_repro/tfidf_vectorizer.pkl
Saved training meta  : models/v4_repro/training_metadata.json

```

### results_v4_repro_min3.txt

```text
========================================================================
NoEsc Offline Training Report
========================================================================
Total sequence samples : 123082
Train samples (70%)    : 86157
Test samples (30%)     : 36925
Train class counts     : {0: np.int64(28932), 1: np.int64(57225)}
Test class counts      : {0: np.int64(12400), 1: np.int64(24525)}
------------------------------------------------------------------------
Accuracy               : 0.997698
Precision              : 0.997963
Recall                 : 0.998573
F1-Score               : 0.998268
False Positive Rate    : 0.004032
Matthews Corrcoef      : 0.994839
------------------------------------------------------------------------
Confusion Matrix (labels: 0=benign, 1=malicious): TN=12350 FP=50 FN=35 TP=24490
========================================================================
Saved SVM model      : models/v4_repro/svm_model.pkl
Saved TF-IDF vect.   : models/v4_repro/tfidf_vectorizer.pkl
Saved training meta  : models/v4_repro/training_metadata.json

```

### results

```text
NoEsc on  ml-bridge-experimentation:main [$!?⇡] via △ v4.3.1 via 🐍 v3.14.3 (.venv) 
❯ python3 src/ml_engine/train_model.py --malicious-dir sample_set/ml_inputs/malicious/ --benign-dir sample_set/ml_inputs/benign/ --model-out models/svm_model.pkl --vectorizer-out models/tfidf_vectorizer.pkl --metadata-out models/training_metadata.json --train-ratio 0.70 --min-events-per-sequence 2
========================================================================
NoEsc Offline Training Report
========================================================================
Total sequence samples : 252495
Train samples (70%)    : 176746
Test samples (30%)     : 75749
Train class counts     : {0: np.int64(33424), 1: np.int64(143322)}
Test class counts      : {0: np.int64(14325), 1: np.int64(61424)}
------------------------------------------------------------------------
Accuracy               : 0.968026
Precision              : 0.970615
Recall                 : 0.990557
F1-Score               : 0.980485
False Positive Rate    : 0.128586
Matthews Corrcoef      : 0.893516
------------------------------------------------------------------------
Confusion Matrix (labels: 0=benign, 1=malicious): TN=12483 FP=1842 FN=580 TP=60844
========================================================================
Saved SVM model      : models/svm_model.pkl
Saved TF-IDF vect.   : models/tfidf_vectorizer.pkl
Saved training meta  : models/training_metadata.json


Semantic workspace search is not currently available

I’ll quickly read your saved metadata file to anchor the analysis with dataset composition and feature-space size, then I’ll give you a practical verdict plus next-step plan.

Read [](file:///home/swuffles/Documents/NoEsc/models/training_metadata.json)

This is a strong result for attack detection, with one important caveat for deployment.

My read:
1. Good news
1. Recall 0.9906 means you are catching about 99.1% of malicious test samples.
2. F1 0.9805 and MCC 0.8935 are both strong.
3. Dataset size is large enough to be meaningful: 252,495 sequence samples in training_metadata.json.

2. Main risk
1. False Positive Rate is 0.1286, so about 12.86% of truly benign samples were flagged malicious.
2. From your confusion matrix, that is 1,842 false alarms out of 14,325 benign test samples.
3. This is the biggest issue if your goal includes low alert fatigue.

What this means in plain terms:
1. Excellent at not missing attacks (low FN: 580 out of 61,424 malicious).
2. Not yet excellent at avoiding benign false alarms (FP: 1,842).
3. Accuracy 0.9680 looks high, but your test set is malicious-heavy, so accuracy alone can hide benign-side pain.

Extra interpretation from your matrix:
1. Specificity (true benign recognition) is 12,483 / (12,483 + 1,842) = 0.8714.
2. Balanced accuracy is roughly (recall + specificity) / 2 = (0.9906 + 0.8714) / 2 = 0.9310.
3. This confirms the model is very strong overall, but weaker on benign discrimination than malicious detection.

How I would analyze and report it:
1. Lead with recall, FPR, and MCC (not accuracy alone).
2. Report class imbalance explicitly:
1. Benign total = 33,424 + 14,325 = 47,749
2. Malicious total = 143,322 + 61,424 = 204,746
3. Add an FP impact statement:
1. “About 12.9% of benign sequences are flagged.”
4. Keep your current run as baseline model.

If you want to reduce false positives next:
1. Re-run with stricter sequence quality:
1. min-events-per-sequence = 3, then 5.
2. Compare FP and recall deltas.
2. Perform false-positive audit:
1. Inspect top benign source files/PIDs that produce FP.
2. Look for recurring maintenance/admin patterns.
3. Do ablation runs:
1. Text only
2. Context only
3. Combined
4. Evaluate threshold-tuning path (decision scores) on validation data to trade small recall loss for large FPR reduction.

Bottom line: very good research baseline, especially for detection power. The next milestone is reducing benign false alarms without collapsing recall.

v3:
python3 src/ml_engine/train_model.py --malicious-dir sample_set/ml_inputs/malicious/ --benign-dir sample_set/ml_inputs/benign/ --model-out models/svm_model.pkl --vectorizer-out models/tfidf_vectorizer.pkl --metadata-out models/training_metadata.json --train-ratio 0.70 --min-events-per-sequence 3
========================================================================
NoEsc Offline Training Report
========================================================================
Total sequence samples : 76978
Train samples (70%)    : 53884
Test samples (30%)     : 23094
Train class counts     : {0: np.int64(28932), 1: np.int64(24952)}
Test class counts      : {0: np.int64(12400), 1: np.int64(10694)}
------------------------------------------------------------------------
Accuracy               : 0.951849
Precision              : 0.905811
Recall                 : 1.000000
F1-Score               : 0.950578
False Positive Rate    : 0.089677
Matthews Corrcoef      : 0.908064
------------------------------------------------------------------------
Confusion Matrix (labels: 0=benign, 1=malicious): TN=11288 FP=1112 FN=0 TP=10694
========================================================================
Saved SVM model      : models/svm_model.pkl
Saved TF-IDF vect.   : models/tfidf_vectorizer.pkl
Saved training meta  : models/training_metadata.json


shittt
NoEsc on  fair-engines [$!?] via △ v4.3.1 via 🐍 v3.14.4 (.venv) 
❯ python3 src/ml_engine/train_model.py --malicious-dir sample_set/training_data/malicious --benign-dir sample_set/training_data/benign --model-out models/v4/svm_model.pkl --vectorizer-out models/v4/tfidf_vectorizer.pkl --metadata-out models/v4/training_metadata.json --train-ratio 0.70 --min-events-per-sequence 2
========================================================================
NoEsc Offline Training Report
========================================================================
Total sequence samples : 367028
Train samples (70%)    : 256919
Test samples (30%)     : 110109
Train class counts     : {0: np.int64(33424), 1: np.int64(223495)}
Test class counts      : {0: np.int64(14325), 1: np.int64(95784)}
------------------------------------------------------------------------
Accuracy               : 0.794967
Precision              : 0.999277
Recall                 : 0.764856
F1-Score               : 0.866492
False Positive Rate    : 0.003700
Matthews Corrcoef      : 0.542850
------------------------------------------------------------------------
Confusion Matrix (labels: 0=benign, 1=malicious): TN=14272 FP=53 FN=22523 TP=73261
========================================================================
Saved SVM model      : models/v4/svm_model.pkl
Saved TF-IDF vect.   : models/v4/tfidf_vectorizer.pkl
Saved training meta  : models/v4/training_metadata.json



```

