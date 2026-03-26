"""
NORMALIZER MODULE

Converts raw VirusTotal data into comparable ratios
"""

def normalize(vt: dict) -> dict:
    total = vt["vt_malicious"] + vt["vt_suspicious"] + vt["vt_harmless"]

    if total == 0:
        return {"mal_ratio": 0, "sus_ratio": 0}

    return {
        "mal_ratio": vt["vt_malicious"] / total,
        "sus_ratio": vt["vt_suspicious"] / total
    }