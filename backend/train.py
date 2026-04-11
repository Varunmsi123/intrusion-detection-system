
import os
import sys
import time
import argparse
import warnings
import joblib
import numpy as np
import pandas as pd
warnings.filterwarnings("ignore")

from sklearn.ensemble           import RandomForestClassifier
from sklearn.tree               import DecisionTreeClassifier
from sklearn.neighbors          import KNeighborsClassifier
from sklearn.linear_model       import LogisticRegression
from sklearn.preprocessing      import LabelEncoder, StandardScaler
from sklearn.model_selection    import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics            import (classification_report, confusion_matrix,
                                        accuracy_score, f1_score,
                                        precision_score, recall_score)
from collections                import Counter

# ── Optional: SMOTE for minority class oversampling ───────────────────────
try:
    from imblearn.over_sampling import SMOTE
    HAS_SMOTE = True
except ImportError:
    HAS_SMOTE = False
    print("[WARN] imbalanced-learn not found. Install with: pip install imbalanced-learn")
    print("       Continuing without SMOTE oversampling.\n")


# ═══════════════════════════════════════════════════════════════════════════
# 1. COLUMN DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════

COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty_level",
]

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

# NSL-KDD label → 5-class attack family
ATTACK_MAP = {
    # Normal
    "normal"          : "Normal",
    # DoS
    "back"            : "DoS", "land"         : "DoS", "neptune"  : "DoS",
    "pod"             : "DoS", "smurf"        : "DoS", "teardrop" : "DoS",
    "apache2"         : "DoS", "udpstorm"     : "DoS", "processtable": "DoS",
    "worm"            : "DoS", "mailbomb"     : "DoS",
    # Probe
    "ipsweep"         : "Probe", "nmap"       : "Probe", "portsweep": "Probe",
    "satan"           : "Probe", "mscan"      : "Probe", "saint"   : "Probe",
    # R2L
    "ftp_write"       : "R2L",  "guess_passwd": "R2L",  "imap"    : "R2L",
    "multihop"        : "R2L",  "phf"         : "R2L",  "spy"     : "R2L",
    "warezclient"     : "R2L",  "warezmaster" : "R2L",  "sendmail": "R2L",
    "named"           : "R2L",  "snmpgetattack": "R2L", "snmpguess": "R2L",
    "xlock"           : "R2L",  "xsnoop"      : "R2L",  "httptunnel": "R2L",
    # U2R
    "buffer_overflow" : "U2R",  "loadmodule"  : "U2R",  "perl"    : "U2R",
    "rootkit"         : "U2R",  "ps"          : "U2R",  "sqlattack": "U2R",
    "xterm"           : "U2R",  "httptunnel"  : "U2R",
}

MODELS_DIR = "models"


# ═══════════════════════════════════════════════════════════════════════════
# 2. DATA LOADING
# ═══════════════════════════════════════════════════════════════════════════

def load_dataset(path: str) -> pd.DataFrame:
    print(f"\n[LOAD] Reading: {path}")

    df = pd.read_csv(path, header=None)

    # ✅ Assign column names (IMPORTANT)
    COLUMNS = [
        "duration","protocol_type","service","flag","src_bytes","dst_bytes",
        "land","wrong_fragment","urgent","hot","num_failed_logins",
        "logged_in","num_compromised","root_shell","su_attempted",
        "num_root","num_file_creations","num_shells","num_access_files",
        "num_outbound_cmds","is_host_login","is_guest_login",
        "count","srv_count","serror_rate","srv_serror_rate",
        "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
        "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
        "dst_host_same_srv_rate","dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
        "dst_host_serror_rate","dst_host_srv_serror_rate",
        "dst_host_rerror_rate","dst_host_srv_rerror_rate",
        "label"
    ]

    df.columns = COLUMNS

    # ✅ Clean label (remove dot)
    df["label"] = df["label"].str.replace(".", "", regex=False)

    print(f"       Shape  : {df.shape}")
    return df


# ═══════════════════════════════════════════════════════════════════════════
# 3. PREPROCESSING
# ═══════════════════════════════════════════════════════════════════════════

def preprocess(df_train: pd.DataFrame,
               df_test:  pd.DataFrame | None = None,
               use_smote: bool = True):
    """
    Full preprocessing pipeline:
      1. Map raw labels → 5-class attack families
      2. Drop irrelevant columns
      3. Remove duplicate rows (key fix for KDD Cup 99 data)
      4. Encode categorical features
      5. Scale numeric features
      6. (Optional) SMOTE oversampling for minority classes

    Returns:
        X_train, X_test, y_train, y_test,
        le_y, scaler, cat_encoders, feature_names
    """
    print("\n[PREPROCESS] Starting preprocessing pipeline...")

    # ── Step 1: Label mapping ──────────────────────────────────────────────
    def map_labels(df):
        if "label" not in df.columns:
            raise ValueError("No 'label' column found in dataset.")
        df = df.copy()
        df["attack_family"] = (
            df["label"]
            .str.strip()
            .str.lower()
            .str.rstrip(".")          # some files have trailing dots
            .map(ATTACK_MAP)
            .fillna("Unknown")        # unseen attacks → Unknown
        )
        n_unknown = (df["attack_family"] == "Unknown").sum()
        if n_unknown > 0:
            print(f"  [WARN] {n_unknown} rows mapped to 'Unknown' (unseen attack types)")
            df = df[df["attack_family"] != "Unknown"].copy()
        return df

    df_train = map_labels(df_train)
    if df_test is not None:
        df_test = map_labels(df_test)

    print(f"  Train class distribution:\n{df_train['attack_family'].value_counts().to_string()}\n")

    # ── Step 2: Drop irrelevant columns ───────────────────────────────────
    drop_cols = ["label", "difficulty_level", "attack_family"]
    feature_cols = [c for c in df_train.columns if c not in drop_cols and c in COLUMNS[:41]]

    # ── Step 3: Remove duplicates ─────────────────────────────────────────
    before = len(df_train)
    df_train = df_train.drop_duplicates(subset=feature_cols)
    after  = len(df_train)
    print(f"  Removed {before - after:,} duplicate rows ({(before-after)/before*100:.1f}%)")

    # ── Step 4: Encode categoricals ───────────────────────────────────────
    cat_encoders = {}
    for col in CATEGORICAL_COLS:
        if col not in df_train.columns:
            continue
        le = LabelEncoder()
        # Fit on train values
        all_vals = list(df_train[col].astype(str).unique())
        if df_test is not None:
            all_vals += list(df_test[col].astype(str).unique())
        le.fit(sorted(set(all_vals)))

        df_train[col] = le.transform(df_train[col].astype(str))
        if df_test is not None:
            # Handle unseen categories in test
            df_test[col] = df_test[col].astype(str).apply(
                lambda x: x if x in le.classes_ else le.classes_[0]
            )
            df_test[col] = le.transform(df_test[col])
        cat_encoders[col] = le

    print(f"  Categorical columns encoded: {list(cat_encoders.keys())}")

    # ── Encode target ──────────────────────────────────────────────────────
    le_y = LabelEncoder()
    y_train_raw = df_train["attack_family"]
    y_test_raw  = df_test["attack_family"] if df_test is not None else None

    # Fit on all known classes to avoid unseen label issues
    all_classes = sorted(set(y_train_raw))
    if y_test_raw is not None:
        all_classes = sorted(set(all_classes) | set(y_test_raw))
    le_y.fit(all_classes)

    y_train = le_y.transform(y_train_raw)
    y_test  = le_y.transform(y_test_raw) if y_test_raw is not None else None

    # ── Coerce remaining object columns to numeric (safety net) ──────────
    for col in feature_cols:
        if df_train[col].dtype == object:
            # Any leftover string column → 0  (should not happen after encoding)
            df_train[col] = pd.to_numeric(df_train[col], errors="coerce").fillna(0)
            if df_test is not None:
                df_test[col] = pd.to_numeric(df_test[col], errors="coerce").fillna(0)

    # ── Build feature matrices ─────────────────────────────────────────────
    X_train = df_train[feature_cols].astype(float).values
    X_test  = df_test[feature_cols].astype(float).values if df_test is not None else None

    print(f"  Feature matrix: {X_train.shape}")
    print(f"  Classes: {list(le_y.classes_)}")

    # ── Step 5: Scale features ────────────────────────────────────────────
    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    if X_test is not None:
        X_test = scaler.transform(X_test)
    print(f"  StandardScaler fitted.")

    # ── Step 6: SMOTE oversampling ─────────────────────────────────────────
    if use_smote and HAS_SMOTE:
        print(f"\n  [SMOTE] Class counts before: {dict(Counter(y_train))}")
        # Only oversample minority classes (R2L, U2R)
        smote = SMOTE(random_state=42, k_neighbors=3)
        try:
            X_train, y_train = smote.fit_resample(X_train, y_train)
            print(f"  [SMOTE] Class counts after : {dict(Counter(y_train))}")
        except Exception as e:
            print(f"  [SMOTE] Skipped: {e}")
    elif use_smote and not HAS_SMOTE:
        print("  [SMOTE] Skipped (imbalanced-learn not installed)")

    # If no separate test file, create a held-out split
    if X_test is None:
        print("\n  No test file provided — creating 25% held-out split")
        X_train, X_test, y_train, y_test = train_test_split(
            X_train, y_train,
            test_size=0.25, random_state=42, stratify=y_train
        )

    print(f"\n  Final → Train: {X_train.shape[0]:,}  Test: {X_test.shape[0]:,}")
    return X_train, X_test, y_train, y_test, le_y, scaler, cat_encoders, feature_cols


# ═══════════════════════════════════════════════════════════════════════════
# 4. MODEL TRAINING
# ═══════════════════════════════════════════════════════════════════════════

def train_all_models(X_train, X_test, y_train, y_test, le_y):
    """Train multiple classifiers and return results dict."""

    classifiers = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            max_features="sqrt",
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=25,
            class_weight="balanced",
            random_state=42,
        ),
        "KNN": KNeighborsClassifier(
            n_neighbors=5,
            n_jobs=-1,
        ),
        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            solver="lbfgs",
            n_jobs=-1,
            random_state=42,
        ),
    }

    results    = {}
    best_f1    = -1
    best_name  = None

    print("\n" + "═"*60)
    print("  MODEL TRAINING")
    print("═"*60)

    for name, clf in classifiers.items():
        print(f"\n  [{name}] Training...")
        t0 = time.time()
        clf.fit(X_train, y_train)
        train_time = time.time() - t0

        y_pred  = clf.predict(X_test)
        acc     = accuracy_score(y_test, y_pred)
        f1      = f1_score(y_test, y_pred, average="weighted", zero_division=0)
        prec    = precision_score(y_test, y_pred, average="weighted", zero_division=0)
        rec     = recall_score(y_test, y_pred, average="weighted", zero_division=0)

        per_class_f1 = f1_score(y_test, y_pred, average=None, zero_division=0)
        per_class    = {le_y.classes_[i]: round(float(per_class_f1[i]), 4)
                        for i in range(len(le_y.classes_))}

        report = classification_report(
            y_test, y_pred,
            target_names=le_y.classes_,
            zero_division=0
        )

        print(f"  Accuracy  : {acc:.4f}")
        print(f"  F1 (wtd)  : {f1:.4f}")
        print(f"  Precision : {prec:.4f}")
        print(f"  Recall    : {rec:.4f}")
        print(f"  Time      : {train_time:.2f}s")
        print(f"  Per-class F1: {per_class}")

        results[name] = {
            "model":       clf,
            "y_pred":      y_pred,
            "accuracy":    acc,
            "f1":          f1,
            "precision":   prec,
            "recall":      rec,
            "train_time":  train_time,
            "per_class_f1": per_class,
            "report":      report,
            "cm":          confusion_matrix(y_test, y_pred),
        }

        if f1 > best_f1:
            best_f1, best_name = f1, name

    print(f"\n  ✓ Best model: {best_name} (F1 = {best_f1:.4f})")
    return results, best_name


# ═══════════════════════════════════════════════════════════════════════════
# 5. SAVE ARTIFACTS
# ═══════════════════════════════════════════════════════════════════════════

def save_artifacts(results, best_name, scaler, le_y, cat_encoders, feature_names):
    """Save all model artifacts to disk."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    best_model = results[best_name]["model"]

    paths = {
        "model":         f"{MODELS_DIR}/random_forest.pkl",
        "scaler":        f"{MODELS_DIR}/scaler.pkl",
        "label_encoder": f"{MODELS_DIR}/label_encoder.pkl",
        "cat_encoders":  f"{MODELS_DIR}/cat_encoders.pkl",
        "feature_names": f"{MODELS_DIR}/feature_names.pkl",
    }

    joblib.dump(best_model,    paths["model"])
    joblib.dump(scaler,        paths["scaler"])
    joblib.dump(le_y,          paths["label_encoder"])
    joblib.dump(cat_encoders,  paths["cat_encoders"])
    joblib.dump(feature_names, paths["feature_names"])

    # Save text report
    report_path = f"{MODELS_DIR}/training_report.txt"

    # ✅ FIX: encoding added
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("IDS Model Training Report\n")
        f.write("="*60 + "\n\n")
        for name, res in results.items():
            marker = " ← SAVED" if name == best_name else ""
            f.write(f"Model: {name}{marker}\n")
            f.write(f"  Accuracy  : {res['accuracy']:.4f}\n")
            f.write(f"  F1 (wtd)  : {res['f1']:.4f}\n")
            f.write(f"  Precision : {res['precision']:.4f}\n")
            f.write(f"  Recall    : {res['recall']:.4f}\n")
            f.write(f"  Train time: {res['train_time']:.2f}s\n")
            f.write("\nClassification Report:\n")
            f.write(res["report"])
            f.write("\n" + "-"*60 + "\n\n")

    print("\n" + "═"*60)
    print("  ARTIFACTS SAVED")
    print("═"*60)
    for key, path in paths.items():
        size = os.path.getsize(path) / 1024
        print(f"  {path:<45} {size:>8.1f} KB")
    print(f"  {report_path}")
    print("═"*60)

    return paths


# ═══════════════════════════════════════════════════════════════════════════
# 6. QUICK INFERENCE TEST
# ═══════════════════════════════════════════════════════════════════════════

def test_inference(paths, X_test, y_test, le_y, n=5):
    """Load saved model from disk and run a quick prediction test."""
    print("\n[INFERENCE TEST] Loading model from disk...")
    model   = joblib.load(paths["model"])
    scaler  = joblib.load(paths["scaler"])   # already applied, just verifying load
    le      = joblib.load(paths["label_encoder"])

    print(f"  Model type : {type(model).__name__}")
    print(f"  Classes    : {list(le.classes_)}")
    print(f"\n  Sample predictions (first {n} test rows):")
    print(f"  {'True':>10}  {'Predicted':>10}  {'Match':>6}")
    print(f"  {'-'*30}")

    for i in range(min(n, len(X_test))):
        row   = X_test[i].reshape(1, -1)   # already scaled
        pred  = le.inverse_transform(model.predict(row))[0]
        true  = le.inverse_transform([y_test[i]])[0]
        conf  = model.predict_proba(row).max()
        match = "✓" if pred == true else "✗"
        print(f"  {true:>10}  {pred:>10}  {match:>6}  conf={conf:.3f}")


# ═══════════════════════════════════════════════════════════════════════════
# 7. MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Train IDS model on NSL-KDD dataset",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # With separate train + test files (recommended for NSL-KDD)
  python train.py --train data/KDDTrain+.txt --test data/KDDTest+.txt

  # With only a training file (25% auto held-out as test)
  python train.py --train data/KDDTrain+.txt

  # Disable SMOTE oversampling
  python train.py --train data/KDDTrain+.txt --no-smote

  # Custom output directory
  python train.py --train data/KDDTrain+.txt --models-dir ./saved_models
        """
    )
    parser.add_argument("--train",      required=True,  help="Path to training dataset (NSL-KDD .txt or .csv)")
    parser.add_argument("--test",       default=None,   help="Path to test dataset (optional)")
    parser.add_argument("--no-smote",   action="store_true", help="Disable SMOTE oversampling")
    parser.add_argument("--models-dir", default="models",    help="Output directory for saved artifacts")
    args = parser.parse_args()

    global MODELS_DIR
    MODELS_DIR = args.models_dir

    print("╔══════════════════════════════════════════════════════════╗")
    print("║        IDS — NSL-KDD Model Trainer                      ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Train file : {args.train}")
    print(f"  Test file  : {args.test or '(none — will split from train)'}")
    print(f"  SMOTE      : {'disabled' if args.no_smote else 'enabled'}")
    print(f"  Output dir : {MODELS_DIR}")

    total_start = time.time()

    # ── Load ───────────────────────────────────────────────────────────────
    df_train = load_dataset(args.train)
    df_test  = load_dataset(args.test) if args.test else None

    # ── Preprocess ─────────────────────────────────────────────────────────
    (X_train, X_test, y_train, y_test,
     le_y, scaler, cat_encoders, feature_names) = preprocess(
        df_train, df_test,
        use_smote=not args.no_smote
    )

    # ── Train ──────────────────────────────────────────────────────────────
    results, best_name = train_all_models(X_train, X_test, y_train, y_test, le_y)

    # ── Save ───────────────────────────────────────────────────────────────
    paths = save_artifacts(results, best_name, scaler, le_y, cat_encoders, feature_names)

    # ── Verify inference works ─────────────────────────────────────────────
    test_inference(paths, X_test, y_test, le_y)

    total_time = time.time() - total_start
    print(f"\n  Total time: {total_time:.1f}s")
    print(f"\n  ✓ Done! Load your model in predict.py with:")
    print(f"    model = joblib.load('{MODELS_DIR}/random_forest.pkl')")
    print(f"    scaler = joblib.load('{MODELS_DIR}/scaler.pkl')")
    print(f"    le     = joblib.load('{MODELS_DIR}/label_encoder.pkl')\n")


if __name__ == "__main__":
    main()
