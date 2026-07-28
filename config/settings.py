"""
config.settings
===============
Central paths and thresholds. Import from here rather than hard-coding.
"""
from pathlib import Path

# Project root = two levels up from this file (config/settings.py -> project/).
ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
LABELED_DIR = DATA_DIR / "labeled"
CAMPAIGN_DIR = DATA_DIR / "campaigns"
STORE_DIR = DATA_DIR / "store"

# THE shared scan-record store (§3.1).
STORE_PATH = STORE_DIR / "scans.db"

# Keyword lists (Module A owns; version-controlled).
KEYWORDS_DIR = ROOT / "csbi" / "common" / "keywords"

# ---- Risk thresholds (Module B consumes; kept here so they're shared) --------
# Applied to scam_probability -> risk_level. Confirm bands against Blueprint §4.3.
RISK_HIGH_THRESHOLD = 0.66
RISK_MEDIUM_THRESHOLD = 0.33

# ---- Trust-score normalisation (§4.1) ---------------------------------------
# T1 uses (1 - norm_subdomain_count). The blueprint leaves the subdomain
# normalisation open; we cap at this many labels (>= cap normalises to 1.0).
# Tweakable — revisit with SHAP weight sensitivity (Blueprint §4, §10).
SUBDOMAIN_NORM_CAP = 3

# ---- CSBI composition --------------------------------------------------------
# C (surface credibility) = mean of these layers' trust scores.
# S (behavioral substance) = mean of these layers' trust scores.
# Reproduces the §5 worked example exactly (see csbi/scoring/csbi.py).
CSBI_C_LAYERS = ("T1", "T2")   # structural + temporal
CSBI_S_LAYERS = ("T3", "T4")   # behavioral + UPI
