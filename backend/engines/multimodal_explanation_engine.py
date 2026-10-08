"""
CYBERGUARD Multimodal Explanation Engine

Generates explainable, transparent syntheses of forensic indicators,
explicitly framing results within prototype boundaries without overclaiming deepfake certainty.
"""

from typing import List, Dict, Any


def generate_multimodal_explanation(
    indicators: List[Dict[str, Any]],
    metadata: Dict[str, Any],
    risk_score: int,
    severity: str
) -> str:
    """
    Synthesizes extracted indicators into a clear, explainable narrative with transparent limitations.
    """
    file_name = metadata.get("file_name", "Uploaded media")
    fmt = metadata.get("file_format", "media")
    dims = metadata.get("dimensions", "unspecified resolution")
    software = metadata.get("software_tool")
    has_exif = metadata.get("has_exif", False)
    has_provenance = metadata.get("has_provenance", False)

    findings = []

    if software:
        findings.append(f"Header inspection identified software marker for '{software}'.")

    if not has_exif and fmt in ("JPEG", "PNG"):
        findings.append("Absence of camera sensor EXIF tags suggests media was re-saved, scraped, or processed through editing software.")

    if has_provenance:
        findings.append("Cryptographic C2PA provenance credentials detected in the container.")
    else:
        findings.append("No cryptographic provenance (C2PA) signature was present to verify chain of custody.")

    for ind in indicators:
        if ind.get("indicator") == "Standard Generative AI Native Resolution":
            findings.append(f"Dimensions ({dims}) correspond to standard synthetic diffusion generation canvas sizes.")

    if not findings:
        findings.append("No obvious anomalies or generative tool markers were detected in the file headers.")

    narrative = (
        f"Forensic header analysis for '{file_name}' ({fmt}, {dims}) resulted in a heuristic risk score of {risk_score}/100 ({severity}). "
        + " ".join(findings) + " "
        + "Note: Metadata inspection serves as an assistive investigative signal. It does not provide cryptographic or absolute certainty of synthetic generation."
    )

    return narrative
