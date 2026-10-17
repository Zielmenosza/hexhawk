#!/usr/bin/env python3
"""Validate HexHawk's current user-facing documentation set."""
from __future__ import annotations

import hashlib
import html
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
CURRENT_MD = [
    ROOT / "README.md",
    ROOT / "KEYBOARD_SHORTCUTS.md",
    ROOT / "PLUGIN_QUICK_REFERENCE.md",
    ROOT / "docs" / "README.md",
    ROOT / "docs" / "HEXHAWK_FOR_DUMMIES.md",
    ROOT / "docs" / "HIGH_ASSURANCE_GUIDE.md",
    ROOT / "docs" / "TESTER_RELEASE_STATUS.md",
    ROOT / "docs" / "FAQ_QUESTION_EVIDENCE.md",
    ROOT / "docs" / "SITE_PRE_RELEASE_REVIEW.md",
    ROOT / "docs" / "PLAIN_LANGUAGE_GLOSSARY.md",
    ROOT / "docs" / "ENGINE_BOUNDARY_DOCTRINE.md",
]
SITE = ROOT / "site-build"
CURRENT_SITE = sorted(SITE.rglob("*.html"))
STALE_UI = [
    "Runtime trace review",
    "Evidence review loop",
    "Input/logic solver",
    "Interactive commands",
    "Extra tools",
]
REQUIRED_UI = [
    "Open a file",
    "Start inspection",
    "Find readable text",
    "Read program instructions",
    "See possible code paths",
    "Overall assessment",
    "Repeat and organize checks",
    "Create a report",
    "Live Debugger",
]

class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.refs: list[tuple[str, str]] = []
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag in {"a", "link"} and values.get("href"):
            self.refs.append(("href", values["href"] or ""))
        if tag in {"img", "script"} and values.get("src"):
            self.refs.append(("src", values["src"] or ""))

class HTMLAuditParser(HTMLParser):
    """Collect release-critical HTML semantics without external dependencies."""
    def __init__(self) -> None:
        super().__init__()
        self.h1_count = 0
        self.ids: list[str] = []
        self.images_missing_alt = 0
        self.controls: list[dict[str, object]] = []
        self.control_stack: list[int] = []
        self.inputs: list[dict[str, str]] = []
        self.labels_for: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "h1":
            self.h1_count += 1
        if tag == "img" and "alt" not in values:
            self.images_missing_alt += 1
        if tag in {"a", "button"}:
            self.controls.append({"tag": tag, "attrs": values, "text": ""})
            self.control_stack.append(len(self.controls) - 1)
        if tag == "input":
            self.inputs.append(values)
        if tag == "label" and values.get("for"):
            self.labels_for.add(values["for"])

    def handle_data(self, data: str) -> None:
        for index in self.control_stack:
            self.controls[index]["text"] = str(self.controls[index]["text"]) + data

    def handle_endtag(self, tag: str) -> None:
        if tag in {"a", "button"} and self.control_stack:
            self.control_stack.pop()

def markdown_refs(text: str) -> list[str]:
    return [match.group(1).strip() for match in re.finditer(r"!?(?:\[[^\]]*\])\(([^)]+)\)", text)]

def check_local_ref(source: Path, ref: str, errors: list[str]) -> None:
    ref = ref.split()[0].strip("<>")
    parts = urlsplit(ref)
    if parts.scheme or ref.startswith(("mailto:", "#", "data:")):
        return
    clean = parts.path
    if not clean:
        return
    if source.suffix.lower() == ".html" and clean.startswith("/"):
        candidate = SITE / clean.lstrip("/")
        candidates = [candidate, candidate / "index.html"]
        if candidate.suffix == "":
            candidates.append(candidate.with_suffix(".html"))
    else:
        candidate = (source.parent / clean).resolve()
        candidates = [candidate, candidate / "index.html"]
    existing = next((path for path in candidates if path.exists()), None)
    if existing is None:
        errors.append(f"broken local reference: {source.relative_to(ROOT)} -> {ref}")
    elif parts.fragment and existing.suffix.lower() == ".html":
        target = existing.read_text(encoding="utf-8")
        fragment = re.escape(parts.fragment)
        if not re.search(rf'(?:id|name)=["\']{fragment}["\']', target):
            errors.append(f"broken local anchor: {source.relative_to(ROOT)} -> {ref}")

def main() -> int:
    errors: list[str] = []
    for path in CURRENT_MD + CURRENT_SITE + [ROOT / "competitive_landscape.html"]:
        if not path.exists():
            errors.append(f"missing current document: {path.relative_to(ROOT)}")
            continue
        text = path.read_text(encoding="utf-8")
        for stale in STALE_UI:
            if stale in text:
                errors.append(f"stale UI term {stale!r}: {path.relative_to(ROOT)}")
        refs = markdown_refs(text) if path.suffix.lower() == ".md" else []
        if path.suffix.lower() == ".html":
            parser = LinkParser(); parser.feed(text)
            refs.extend(ref for _, ref in parser.refs)
            audit = HTMLAuditParser(); audit.feed(text)
            rel = path.relative_to(ROOT)
            if not re.search(r'<html\b[^>]*\blang=["\']en["\']', text, flags=re.IGNORECASE):
                errors.append(f"English page missing html lang: {rel}")
            if not re.search(r'<meta\b[^>]*\bname=["\']viewport["\']', text, flags=re.IGNORECASE):
                errors.append(f"page missing viewport metadata: {rel}")
            if not re.search(r'<title>\s*[^<]+\s*</title>', text, flags=re.IGNORECASE):
                errors.append(f"page missing descriptive title: {rel}")
            if 'href="#main-content"' not in text or 'id="main-content"' not in text:
                errors.append(f"page missing working skip link: {rel}")
            if audit.h1_count != 1:
                errors.append(f"page must contain exactly one h1 ({audit.h1_count} found): {rel}")
            duplicate_ids = sorted({item for item in audit.ids if audit.ids.count(item) > 1})
            if duplicate_ids:
                errors.append(f"duplicate HTML ids in {rel}: {', '.join(duplicate_ids)}")
            if audit.images_missing_alt:
                errors.append(f"images missing alt attributes ({audit.images_missing_alt}): {rel}")
            for control in audit.controls:
                attrs = control["attrs"]
                assert isinstance(attrs, dict)
                name = " ".join(str(control["text"]).split()) or attrs.get("aria-label", "") or attrs.get("title", "")
                if not name:
                    errors.append(f"unnamed {control['tag']} control: {rel}")
                if name.lower() in {"click here", "here", "learn more", "read more"}:
                    errors.append(f"ambiguous link label {name!r}: {rel}")
                if attrs.get("target") == "_blank" and "noopener" not in attrs.get("rel", ""):
                    errors.append(f"target=_blank link missing rel=noopener: {rel}")
            for item in audit.inputs:
                if item.get("type", "text").lower() == "hidden":
                    continue
                input_id = item.get("id", "")
                if not item.get("aria-label") and not item.get("title") and (not input_id or input_id not in audit.labels_for):
                    errors.append(f"unlabelled input: {rel}")
        for ref in refs:
            check_local_ref(path, ref, errors)
    combined = "\n".join(path.read_text(encoding="utf-8") for path in CURRENT_MD if path.exists())
    for label in REQUIRED_UI:
        if label not in combined:
            errors.append(f"current UI label absent from Markdown set: {label}")
    active_site_text = "\n".join(path.read_text(encoding="utf-8") for path in CURRENT_SITE)
    for vague in ["synergy", "bespoke ideation", "headless architecture", "cutting-edge", "world-class", "game-changing"]:
        if re.search(rf"\b{re.escape(vague)}\b", active_site_text, flags=re.IGNORECASE):
            errors.append(f"vague promotional phrase remains in active site: {vague}")
    if re.search(r"frequently asked", active_site_text, flags=re.IGNORECASE):
        errors.append("active site claims questions are frequently asked without frequency evidence")
    home_text = (SITE / "index.html").read_text(encoding="utf-8")
    home_hero = re.search(r'<section class="hero[^>]*>(.*?)</section>', home_text, flags=re.DOTALL)
    if not home_hero:
        errors.append("home page is missing its primary hero")
    else:
        for internal_name in ["GYRE", "NEST", "AETHERFRAME", "TALON", "STRIKE", "ECHO", "CREST"]:
            if internal_name in home_hero.group(1):
                errors.append(f"home hero leads with internal name instead of user outcome: {internal_name}")
    for route in ["/features", "/pricing", "/contact", "/apply"]:
        if f'href="{route}"' not in home_text:
            errors.append(f"home page does not expose decision route directly: {route}")
    standard_nav = ["How it works", "Pricing", "Trust", "Docs", "FAQ", "Contact", "Apply to test"]
    for path in [SITE / "index.html", SITE / "features" / "index.html", SITE / "pricing" / "index.html", SITE / "trust" / "index.html", SITE / "docs" / "index.html", SITE / "faq" / "index.html", SITE / "apply" / "index.html", SITE / "contact" / "index.html"]:
        page_text = path.read_text(encoding="utf-8")
        nav = re.search(r'<nav\b[^>]*aria-label="Primary navigation"[^>]*>(.*?)</nav>', page_text, flags=re.DOTALL)
        if not nav or any(label not in nav.group(1) for label in standard_nav):
            errors.append(f"plain decision navigation is incomplete: {path.relative_to(ROOT)}")
    styles = (SITE / "assets" / "styles.css").read_text(encoding="utf-8")
    for accessibility_rule in [":focus-visible", "prefers-reduced-motion", "min-height: 44px", ".skip-link"]:
        if accessibility_rule not in styles:
            errors.append(f"shared stylesheet missing accessibility rule: {accessibility_rule}")
    app_script = (SITE / "assets" / "app.js").read_text(encoding="utf-8")
    if "document.documentElement.classList.add('js')" not in app_script or ".js .links" not in styles:
        errors.append("mobile navigation lacks a no-JavaScript fallback")
    htaccess = (SITE / ".htaccess").read_text(encoding="utf-8")
    for private_artifact_pattern in ["\\.(exe|msi|sig)$", "SHA256SUMS\\.txt", "checksums\\.txt", "latest\\.json"]:
        if private_artifact_pattern not in htaccess:
            errors.append(f"web-server rules do not deny public release artifact: {private_artifact_pattern}")
    privacy_text = (SITE / "privacy" / "index.html").read_text(encoding="utf-8")
    for privacy_boundary in ["not a final legal privacy policy", "Retention and deletion periods", "Operator or data-controller identity", "Cookies or analytics behavior"]:
        if privacy_boundary not in privacy_text:
            errors.append(f"preview privacy limitations omit required boundary: {privacy_boundary}")
    pricing_text = (SITE / "pricing" / "index.html").read_text(encoding="utf-8")
    for offer_boundary in ["proposed one-time preview seat", "rough indicator only", "complete written offer", "does not create a complete public offer or payment request by itself"]:
        if offer_boundary not in pricing_text:
            errors.append(f"Founder pricing lacks written-offer boundary: {offer_boundary}")
    if 'id="essential-facts"' not in (SITE / "faq" / "index.html").read_text(encoding="utf-8"):
        errors.append("FAQ hides all essential access and safety facts inside collapsed details")
    known_text = (SITE / "known-issues" / "index.html").read_text(encoding="utf-8")
    for conditional in ["Packages may be unsigned", "Updates may not be automatic", "P2 wording"]:
        if conditional in known_text:
            errors.append(f"Known Issues uses stale or internal current-channel wording: {conditional}")
    review_text = (ROOT / "docs" / "SITE_PRE_RELEASE_REVIEW.md").read_text(encoding="utf-8")
    for source_name in ["Binary Ninja", "IDA Pro", "Ghidra", "Cutter", "Malcat", "WCAG 2.2"]:
        if source_name not in review_text:
            errors.append(f"pre-release review missing benchmark provenance: {source_name}")
    faq_path = SITE / "faq" / "index.html"
    if faq_path.exists():
        faq_text = faq_path.read_text(encoding="utf-8")
        question_count = len(re.findall(r'<details class="faq-item">', faq_text))
        if question_count < 30:
            errors.append(f"FAQ coverage unexpectedly low: {question_count} questions")
        for anchor in ['id="files"', 'id="trust-answers"', 'id="install"', 'id="support"']:
            if anchor not in faq_text:
                errors.append(f"FAQ missing section anchor: {anchor}")
        questions = [
            html.unescape(re.sub(r"<[^>]+>", "", item)).strip()
            for item in re.findall(r"<summary>(.*?)</summary>", faq_text, flags=re.DOTALL)
        ]
        evidence_text = (ROOT / "docs" / "FAQ_QUESTION_EVIDENCE.md").read_text(encoding="utf-8")
        mapped_questions = [
            match.group(1).strip()
            for match in re.finditer(r"^\|\s*\d+\s*\|\s*([^|]+?)\s*\|", evidence_text, flags=re.MULTILINE)
        ]
        if questions != mapped_questions:
            errors.append("FAQ question inventory differs from FAQ_QUESTION_EVIDENCE.md")
        if "Where are license details stored?" in faq_text:
            errors.append("unsupported license-storage question remains in FAQ")
    sitemap = (SITE / "sitemap.xml").read_text(encoding="utf-8")
    for route in ["faq", "apply", "contact", "known-issues", "privacy"]:
        if f"https://hexhawk.ke/{route}/" not in sitemap:
            errors.append(f"{route} absent from sitemap")
    hermes_text = (SITE / "hermes" / "index.html").read_text(encoding="utf-8")
    if 'name="robots" content="noindex, nofollow"' not in hermes_text:
        errors.append("private owner-only Hermes page is not marked noindex, nofollow")
    if "https://hexhawk.ke/hermes/" in sitemap:
        errors.append("private owner-only Hermes page remains in the public sitemap")
    for path in CURRENT_SITE:
        relative = path.relative_to(SITE).as_posix()
        if relative in {"404.html", "hermes/index.html"}:
            continue
        page_text = path.read_text(encoding="utf-8")
        canonical = re.search(r'<link\s+rel="canonical"\s+href="([^"]+)"', page_text, flags=re.IGNORECASE)
        if not canonical or canonical.group(1) not in sitemap:
            errors.append(f"public page canonical absent from sitemap: {path.relative_to(ROOT)}")
    for path in [SITE / "index.html", SITE / "features" / "index.html", SITE / "pricing" / "index.html", SITE / "trust" / "index.html", SITE / "downloads" / "index.html", SITE / "docs" / "index.html", SITE / "apply" / "index.html", SITE / "contact" / "index.html", SITE / "known-issues" / "index.html", SITE / "privacy" / "index.html"]:
        if 'data-path="/faq"' not in path.read_text(encoding="utf-8"):
            errors.append(f"FAQ absent from primary navigation: {path.relative_to(ROOT)}")
    source = (ROOT / "competitive_landscape.html").read_bytes()
    mirror = (SITE / "competitive_landscape.html").read_bytes()
    if source != mirror:
        errors.append("competitive landscape source and site mirror differ")
    installer = ROOT / "target" / "release" / "bundle" / "nsis" / "HexHawk_1.0.0_x64-setup.exe"
    sidecar = installer.with_suffix(installer.suffix + ".sha256")
    if installer.exists() and sidecar.exists():
        expected = sidecar.read_text(encoding="utf-8").split()[0].lower()
        actual = hashlib.sha256(installer.read_bytes()).hexdigest()
        if expected != actual:
            errors.append("installer checksum sidecar does not match the current NSIS artifact")
        for current_record in [ROOT / "docs" / "TESTER_RELEASE_STATUS.md", SITE / "downloads" / "index.html"]:
            if expected not in current_record.read_text(encoding="utf-8").lower():
                errors.append(f"current artifact hash absent from {current_record.relative_to(ROOT)}")
    manifest_path = ROOT / "docs" / "assets" / "hexhawk-for-dummies" / "capture_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not manifest.get("native_tauri_proven") or manifest.get("runtime_mode") != "native-production-webview":
        errors.append("screenshot manifest does not prove native production-WebView mode")
    for entry in manifest.get("entries", []):
        image = manifest_path.parent / entry["filename"]
        if not image.exists():
            errors.append(f"missing screenshot: {image.relative_to(ROOT)}")
            continue
        digest = hashlib.sha256(image.read_bytes()).hexdigest()
        if digest != entry.get("sha256"):
            errors.append(f"screenshot hash mismatch: {image.relative_to(ROOT)}")
    if errors:
        print("DOCUMENTATION VALIDATION FAILED")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"DOCUMENTATION VALIDATION PASSED: {len(CURRENT_MD)} Markdown files, {len(CURRENT_SITE)} site pages, {len(manifest['entries'])} current screenshots")
    return 0

if __name__ == "__main__":
    sys.exit(main())
