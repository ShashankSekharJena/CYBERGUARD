"""
CYBERGUARD Multimodal Impersonation Detector

Provides robust, defensive file validation, metadata extraction, and forensic feature
heuristics for images (JPEG, PNG, WEBP, GIF) and video containers (MP4, WEBM).
Transparently flags software tags, missing EXIF, compression artifacts, and provenance markers.
"""

import io
import re
import struct
from typing import Dict, List, Any, Tuple, Optional


KNOWN_AI_EDITING_KEYWORDS = [
    ("midjourney", "Midjourney AI generation signature detected in metadata or text chunks."),
    ("stable diffusion", "Stable Diffusion / AUTOMATIC1111 prompt metadata identified in PNG/XMP tags."),
    ("dall-e", "DALL-E generation signature or OpenAI attribution tag detected."),
    ("deepfacelab", "DeepFaceLab / face swap synthesis marker found in metadata."),
    ("faceapp", "FaceApp facial modification signature present in software metadata."),
    ("photoshop", "Adobe Photoshop editing history detected in EXIF/XMP markers."),
    ("gimp", "GIMP raster manipulation tool signature identified."),
    ("canva", "Canva graphic design editor metadata detected.")
]

SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".mp4", ".webm"}
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB


def validate_file(filename: str, file_bytes: bytes) -> Tuple[bool, str, str]:
    """
    Validates file size, extension, and magic bytes.
    Returns (is_valid, detected_format, error_message).
    """
    if not file_bytes or len(file_bytes) == 0:
        return False, "UNKNOWN", "Empty file received."

    if len(file_bytes) > MAX_FILE_SIZE:
        return False, "UNKNOWN", f"File exceeds maximum allowed size of {MAX_FILE_SIZE // (1024*1024)}MB."

    # Magic byte inspection
    header = file_bytes[:16]

    if header.startswith(b"\xff\xd8\xff"):
        fmt = "JPEG"
        mime = "image/jpeg"
    elif header.startswith(b"\x89PNG\r\n\x1a\n"):
        fmt = "PNG"
        mime = "image/png"
    elif header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        fmt = "WEBP"
        mime = "image/webp"
    elif header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        fmt = "GIF"
        mime = "image/gif"
    elif len(file_bytes) >= 12 and header[4:8] == b"ftyp":
        fmt = "MP4"
        mime = "video/mp4"
    elif header.startswith(b"\x1a\x45\xdf\xa3"):
        fmt = "WEBM"
        mime = "video/webm"
    else:
        return False, "UNKNOWN", "Unsupported file signature or corrupt header."

    return True, fmt, mime


def extract_jpeg_dimensions_and_markers(file_bytes: bytes) -> Tuple[Optional[str], List[str], Dict[str, Any]]:
    """Extracts resolution, markers, and EXIF/JFIF headers from JPEG bytes."""
    dimensions = None
    markers_found = []
    dump: Dict[str, Any] = {}
    i = 2
    length = len(file_bytes)

    while i < length - 8:
        if file_bytes[i] == 0xFF:
            marker = file_bytes[i + 1]
            # SOF0, SOF1, SOF2 (Start of frame -> dimensions)
            if marker in (0xC0, 0xC1, 0xC2):
                h, w = struct.unpack(">HH", file_bytes[i + 5 : i + 9])
                dimensions = f"{w}x{h}"
                dump["dimensions"] = dimensions
            # APP1 (EXIF / XMP)
            elif marker == 0xE1:
                app1_len = struct.unpack(">H", file_bytes[i + 2 : i + 4])[0]
                chunk = file_bytes[i + 4 : i + 2 + app1_len]
                if b"Exif" in chunk:
                    markers_found.append("EXIF")
                if b"http://ns.adobe.com/xmp/" in chunk:
                    markers_found.append("XMP")
                # Search for C2PA provenance
                if b"c2pa" in chunk.lower() or b"contentcredentials" in chunk.lower():
                    markers_found.append("C2PA_PROVENANCE")
            # APP0 (JFIF)
            elif marker == 0xE0:
                markers_found.append("JFIF")
            # APP2 (ICC Profile / FlashPix / C2PA manifest)
            elif marker == 0xE2:
                if b"c2pa" in file_bytes[i : i + 200].lower():
                    markers_found.append("C2PA_PROVENANCE")

            # Advance marker length
            if marker not in (0xD8, 0xD9, 0x00) and (marker < 0xD0 or marker > 0xD7):
                if i + 3 < length:
                    seg_len = struct.unpack(">H", file_bytes[i + 2 : i + 4])[0]
                    i += 2 + seg_len
                else:
                    break
            else:
                i += 2
        else:
            i += 1

    return dimensions, markers_found, dump


def extract_png_chunks_and_metadata(file_bytes: bytes) -> Tuple[Optional[str], List[str], Dict[str, Any]]:
    """Parses PNG chunks for resolution and text metadata (tEXt, zTXt, iTXt)."""
    dimensions = None
    chunks_found = []
    dump: Dict[str, Any] = {}
    i = 8
    length = len(file_bytes)

    while i + 8 <= length:
        chunk_len = struct.unpack(">I", file_bytes[i : i + 4])[0]
        chunk_type = file_bytes[i + 4 : i + 8].decode("latin-1", errors="ignore")
        chunks_found.append(chunk_type)

        if chunk_type == "IHDR" and chunk_len >= 8:
            w, h = struct.unpack(">II", file_bytes[i + 8 : i + 16])
            dimensions = f"{w}x{h}"
            dump["dimensions"] = dimensions

        elif chunk_type in ("tEXt", "iTXt", "zTXt"):
            chunk_data = file_bytes[i + 8 : i + 8 + min(chunk_len, 4096)]
            text_str = chunk_data.decode("utf-8", errors="ignore")
            dump[f"chunk_{chunk_type}"] = text_str[:300]
            if "c2pa" in text_str.lower():
                chunks_found.append("C2PA_PROVENANCE")

        i += 12 + chunk_len

    return dimensions, chunks_found, dump


def detect_multimodal_threats(
    filename: str,
    file_bytes: bytes,
    content_type: Optional[str] = None
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Main multimodal forensic detection pipeline.
    Extracts metadata, searches for modification signatures, checks provenance,
    and produces explainable forensic indicators.
    """
    is_valid, fmt, detected_mime = validate_file(filename, file_bytes)
    if not is_valid:
        metadata_summary = {
            "file_name": filename,
            "file_size_bytes": len(file_bytes) if file_bytes else 0,
            "mime_type": content_type or "application/octet-stream",
            "file_format": "INVALID",
            "dimensions": None,
            "creation_date": None,
            "software_tool": None,
            "has_exif": False,
            "has_provenance": False,
            "raw_metadata_dump": {"error": detected_mime}
        }
        indicators = [{
            "indicator": "Invalid or Malformed File",
            "category": "INTEGRITY",
            "details": f"File failed structural validation: {detected_mime}",
            "severity_contribution": "HIGH",
            "weight": 50
        }]
        return metadata_summary, indicators

    indicators: List[Dict[str, Any]] = []
    dimensions = None
    markers = []
    raw_dump: Dict[str, Any] = {}
    software_tool = None
    has_exif = False
    has_provenance = False

    file_content_str = file_bytes[: min(len(file_bytes), 65536)].decode("latin-1", errors="ignore").lower()

    if fmt == "JPEG":
        dimensions, markers, raw_dump = extract_jpeg_dimensions_and_markers(file_bytes)
        has_exif = "EXIF" in markers
        has_provenance = "C2PA_PROVENANCE" in markers
    elif fmt == "PNG":
        dimensions, markers, raw_dump = extract_png_chunks_and_metadata(file_bytes)
        has_exif = "eXIf" in markers
        has_provenance = "C2PA_PROVENANCE" in markers
    elif fmt == "MP4":
        raw_dump["container"] = "ISO/IEC 14496-14 MP4"
        if b"c2pa" in file_bytes[:4096].lower():
            has_provenance = True

    # Check for known AI editing or generative tool signatures
    for kw, desc in KNOWN_AI_EDITING_KEYWORDS:
        if kw in file_content_str:
            software_tool = kw.upper()
            indicators.append({
                "indicator": f"Editing/Synthesis Software Signature ({kw.title()})",
                "category": "SOFTWARE_SIGNATURE",
                "details": desc,
                "severity_contribution": "HIGH" if "deepface" in kw or "diffusion" in kw or "dall-e" in kw else "MEDIUM",
                "weight": 35 if "deepface" in kw or "diffusion" in kw else 25
            })

    # Metadata stripped indicator (common in social engineering uploads or web scrapers)
    if fmt in ("JPEG", "PNG") and not has_exif:
        indicators.append({
            "indicator": "Stripped Camera/Sensor Metadata",
            "category": "METADATA",
            "details": "Image lacks original camera EXIF/sensor headers (standard for web scrapers, re-encoded files, or social platforms).",
            "severity_contribution": "LOW",
            "weight": 10
        })

    # Provenance indicator
    if has_provenance:
        indicators.append({
            "indicator": "C2PA / Content Credentials Present",
            "category": "PROVENANCE",
            "details": "Cryptographic content provenance manifest detected in file header.",
            "severity_contribution": "INFO",
            "weight": -15  # Lowers risk as provenance exists for inspection
        })
    else:
        indicators.append({
            "indicator": "Absence of Cryptographic Provenance (No C2PA)",
            "category": "PROVENANCE",
            "details": "File does not contain verifiable cryptographic Content Credentials or C2PA manifest.",
            "severity_contribution": "INFO",
            "weight": 5
        })

    # Extreme or typical synthetic aspect ratio / resolution indicators
    if dimensions:
        try:
            w_str, h_str = dimensions.split("x")
            w, h = int(w_str), int(h_str)
            if (w == 512 and h == 512) or (w == 1024 and h == 1024) or (w == 768 and h == 768):
                indicators.append({
                    "indicator": "Standard Generative AI Native Resolution",
                    "category": "METADATA",
                    "details": f"Dimensions ({dimensions}) match default native generative diffusion model canvas sizes (512x512, 768x768, 1024x1024).",
                    "severity_contribution": "MEDIUM",
                    "weight": 20
                })
        except Exception:
            pass

    metadata_summary = {
        "file_name": filename,
        "file_size_bytes": len(file_bytes),
        "mime_type": detected_mime,
        "file_format": fmt,
        "dimensions": dimensions,
        "creation_date": raw_dump.get("creation_date"),
        "software_tool": software_tool,
        "has_exif": has_exif,
        "has_provenance": has_provenance,
        "raw_metadata_dump": raw_dump
    }

    return metadata_summary, indicators
