"""
CYBERGUARD Multimodal Response Engine

Generates tailored defensive recommendations and manual verification procedures
for suspicious or potentially synthetic multimedia files.
"""

from typing import List, Dict, Any


def generate_multimodal_recommendations(
    indicators: List[Dict[str, Any]],
    metadata: Dict[str, Any],
    severity: str
) -> List[str]:
    """
    Generates actionable, defensive manual verification guidelines for analysts.
    """
    actions = [
        "Conduct out-of-band verification with the purported sender or subject before taking actions based on this media.",
        "Perform a reverse image search (e.g. Google Lens, TinEye) to inspect prior indexed occurrences and original contexts.",
        "Inspect image edges, background geometries, earlobes, teeth, and reflection symmetry for generative synthesis artifacts.",
        "Verify file origin and cryptographic signature with the media source if provenance is required.",
        "If media involves financial, executive, or credential requests, verify identity via official corporate voice/video channels."
    ]

    software = metadata.get("software_tool")
    if software:
        actions.insert(0, f"Investigate context surrounding detected editing software tag ({software}) to verify legitimate authorization.")

    return actions
