import os
import joblib
import numpy as np
from datetime import datetime, timezone
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sqlalchemy.orm import Session

MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml"))
MODEL_PATH = os.path.join(MODEL_DIR, "model.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")

_model_cache = None
_scaler_cache = None

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "subdomain_count",
    "dot_count",
    "hyphen_count",
    "special_char_count",
    "has_ip",
    "has_at_symbol",
    "has_punycode",
    "parameter_count",
    "has_suspicious_keywords",
    "https_enabled",
    "ssl_valid",
    "brand_impersonated"
]

def encode_features_to_vector(features_dict: dict) -> np.ndarray:
    """Encodes a feature vector dictionary into a numpy 1D array for ML model input."""
    vec = [
        float(features_dict.get("url_length", 30)),
        float(features_dict.get("hostname_length", 15)),
        float(features_dict.get("subdomain_count", 1)),
        float(features_dict.get("dot_count", 2)),
        float(features_dict.get("hyphen_count", 0)),
        float(features_dict.get("special_char_count", 0)),
        1.0 if features_dict.get("has_ip", False) else 0.0,
        1.0 if features_dict.get("has_at_symbol", False) else 0.0,
        1.0 if features_dict.get("has_punycode", False) else 0.0,
        float(features_dict.get("parameter_count", 0)),
        1.0 if features_dict.get("has_suspicious_keywords", False) else 0.0,
        1.0 if features_dict.get("https_enabled", True) else 0.0,
        1.0 if features_dict.get("ssl_valid", True) is not False else 0.0,
        1.0 if features_dict.get("brand_impersonated") else 0.0
    ]
    return np.array(vec).reshape(1, -1)

def generate_synthetic_training_data(n_samples: int = 1000):
    """Generates synthetic cybersecurity URL dataset for model training."""
    np.random.seed(42)
    X = []
    y = []

    for _ in range(n_samples):
        is_phishing = np.random.choice([0, 1], p=[0.5, 0.5])
        if is_phishing:
            url_length = np.random.randint(60, 150)
            hostname_length = np.random.randint(25, 60)
            subdomains = np.random.randint(2, 6)
            dots = np.random.randint(3, 8)
            hyphens = np.random.randint(1, 6)
            special_chars = np.random.randint(2, 10)
            has_ip = np.random.choice([0, 1], p=[0.7, 0.3])
            has_at = np.random.choice([0, 1], p=[0.8, 0.2])
            has_punycode = np.random.choice([0, 1], p=[0.85, 0.15])
            params = np.random.randint(1, 6)
            suspicious_kw = np.random.choice([0, 1], p=[0.2, 0.8])
            https = np.random.choice([0, 1], p=[0.6, 0.4])
            ssl_valid = np.random.choice([0, 1], p=[0.7, 0.3])
            brand_imp = np.random.choice([0, 1], p=[0.4, 0.6])
        else:
            url_length = np.random.randint(15, 55)
            hostname_length = np.random.randint(8, 22)
            subdomains = np.random.randint(0, 2)
            dots = np.random.randint(1, 3)
            hyphens = np.random.randint(0, 2)
            special_chars = np.random.randint(0, 3)
            has_ip = 0
            has_at = 0
            has_punycode = 0
            params = np.random.randint(0, 2)
            suspicious_kw = np.random.choice([0, 1], p=[0.95, 0.05])
            https = 1
            ssl_valid = 1
            brand_imp = 0

        vec = [url_length, hostname_length, subdomains, dots, hyphens, special_chars,
               has_ip, has_at, has_punycode, params, suspicious_kw, https, ssl_valid, brand_imp]
        X.append(vec)
        y.append(is_phishing)

    return np.array(X), np.array(y)

def train_and_persist_model(db: Session = None, version_tag: str = None) -> dict:
    """Trains a Random Forest Classifier model, saves artifacts, and records metadata in database."""
    os.makedirs(MODEL_DIR, exist_ok=True)
    X, y = generate_synthetic_training_data(1200)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    clf.fit(X_scaled, y)

    y_pred = clf.predict(X_scaled)
    y_prob = clf.predict_proba(X_scaled)[:, 1]

    metrics = {
        "accuracy": round(float(accuracy_score(y, y_pred)), 4),
        "precision": round(float(precision_score(y, y_pred)), 4),
        "recall": round(float(recall_score(y, y_pred)), 4),
        "f1_score": round(float(f1_score(y, y_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y, y_prob)), 4)
    }

    joblib.dump(clf, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    global _model_cache, _scaler_cache
    _model_cache = clf
    _scaler_cache = scaler

    version_name = version_tag or f"v1.{datetime.now(timezone.utc).strftime('%m%d.%H%M')}"

    if db:
        from app.models.scan import ModelVersion
        # Deactivate older models
        db.query(ModelVersion).update({"is_active": False})
        
        new_mv = ModelVersion(
            version=version_name,
            algorithm="Random Forest Classifier (Scikit-Learn)",
            metrics=metrics,
            is_active=True
        )
        db.add(new_mv)
        db.commit()

    return {
        "version": version_name,
        "algorithm": "Random Forest Classifier (Scikit-Learn)",
        "metrics": metrics
    }

def get_loaded_model():
    """Loads cached model or initializes a trained model."""
    global _model_cache, _scaler_cache
    if _model_cache is not None and _scaler_cache is not None:
        return _model_cache, _scaler_cache

    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        try:
            _model_cache = joblib.load(MODEL_PATH)
            _scaler_cache = joblib.load(SCALER_PATH)
            return _model_cache, _scaler_cache
        except Exception:
            pass

    # If model files do not exist yet, train now
    train_and_persist_model()
    return _model_cache, _scaler_cache

def predict_phishing_probability(features_dict: dict) -> float:
    """Predicts phishing probability (0.0 to 1.0) for a given URL feature dictionary."""
    try:
        model, scaler = get_loaded_model()
        vec = encode_features_to_vector(features_dict)
        vec_scaled = scaler.transform(vec)
        prob = model.predict_proba(vec_scaled)[0][1]
        return round(float(prob), 4)
    except Exception:
        # Fallback estimation if ML prediction encounters unexpected error
        return 0.50
