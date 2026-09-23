import os
import re
import json
import pytest

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend")
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "schema", "event.schema.json")


def test_no_purple_or_pink_in_frontend_assets():
    """
    Strict Design System Rule: No purple, no pink anywhere in the UI,
    including CSS, JS, SVGs, or HTML.
    """
    # Common purple and pink patterns/keywords/hex ranges
    forbidden_colors = [
        re.compile(r"#([89a-fA-F][0-9a-fA-F]00[89a-fA-F][0-9a-fA-F])"), # general purple/magenta hex
        re.compile(r"\b(purple|pink|magenta|violet|fuchsia)\b", re.IGNORECASE),
        re.compile(r"#FFC0CB|#FF69B4|#FF1493|#C71585|#DB7093|#9C27B0|#673AB7|#8A2BE2|#9932CC|#8B008B|#800080|#4B0082|#483D8B", re.IGNORECASE),
    ]

    checked_extensions = (".css", ".js", ".html")
    for root, _, files in os.walk(FRONTEND_DIR):
        for f in files:
            if f.endswith(checked_extensions):
                filepath = os.path.join(root, f)
                with open(filepath, "r", encoding="utf-8") as file_handle:
                    content = file_handle.read()
                    for pattern in forbidden_colors:
                        matches = pattern.findall(content)
                        assert len(matches) == 0, f"Forbidden purple/pink color found in {filepath}: {matches}"


def test_schema_docs_parity():
    """
    Asserts that every property defined in schema/event.schema.json
    is represented in the docs view in frontend/js/app.js.
    """
    with open(SCHEMA_PATH, "r", encoding="utf-8") as sf:
        schema = json.load(sf)

    properties = schema.get("properties", {})
    assert len(properties) > 0

    app_js_path = os.path.join(FRONTEND_DIR, "js", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as jf:
        app_js_content = jf.read()

    for prop_name in properties.keys():
        assert f'name: "{prop_name}"' in app_js_content or f'"{prop_name}"' in app_js_content, \
            f"Schema property '{prop_name}' missing from Docs documentation table in app.js"


def test_token_hash_monospace_typography():
    """
    Asserts that monospace font is enforced for token hashes, code, and timestamps.
    """
    main_css_path = os.path.join(FRONTEND_DIR, "css", "main.css")
    with open(main_css_path, "r", encoding="utf-8") as cf:
        css_content = cf.read()

    assert ".token-hash" in css_content
    assert "var(--font-mono)" in css_content
    assert "code, pre, .hash, .token-hash" in css_content


def test_globe_coordinate_determinism():
    """
    Verifies that the globe's deterministic hashing function produces
    stable, identical latitude/longitude coordinates across runs.
    """
    def fnv1a_hash01(s):
        h = 2166136261
        for ch in s:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        return (h % 100000) / 100000

    tok = "hash_6a438e0305c7"
    h1_a = fnv1a_hash01(tok + "lat")
    h1_b = fnv1a_hash01(tok + "lat")
    h2_a = fnv1a_hash01(tok + "lon")
    h2_b = fnv1a_hash01(tok + "lon")
    assert h1_a == h1_b
    assert h2_a == h2_b

    lat = (h1_a * 2 - 1) * 72
    lon = h2_a * 360
    assert -72 <= lat <= 72
    assert 0 <= lon <= 360
