import os
import re
import json
from typing import Dict, List, Tuple, Optional


VULN_MARKER_RE = re.compile(r"//\s*<yes>\s*<report>\s*([A-Za-z0-9_]+)", re.IGNORECASE)
SOURCE_RE = re.compile(r"@source:\s*(.+)")
VULN_AT_LINES_RE = re.compile(r"@vulnerable_at_lines:\s*(.+)")
PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)


def extract_source(raw_text: str) -> Optional[str]:
    m = SOURCE_RE.search(raw_text)
    if not m:
        return None
    return m.group(1).strip()


def extract_pragma_version(raw_text: str) -> Optional[str]:
    """
    Returns a compact version like '0.4.0' from 'pragma solidity ^0.4.0;'
    If it cannot normalize, returns the full pragma spec (e.g., '^0.8.25').
    """
    m = PRAGMA_RE.search(raw_text)
    if not m:
        return None

    spec = m.group(1).strip()  # e.g. '^0.4.0' or '>=0.8.0 <0.9.0'
    # try to grab the first X.Y.Z occurrence
    vm = re.search(r"(\d+\.\d+\.\d+)", spec)
    return vm.group(1) if vm else spec


def strip_comments_build_mapping(raw_text: str) -> Tuple[str, Dict[int, int], Dict[int, str]]:
    """
    Produces:
      - cleaned solidity content (no // or /* */ comments, no empty lines)
      - mapping from ORIGINAL line -> CLEANED line (only for lines that survive)
      - code_text_by_orig_line: original line -> code-only text (comments stripped), '' if no code
    Remove comments + empty lines + strip
    """
    lines = raw_text.splitlines()
    in_block = False

    cleaned_lines: List[str] = []
    orig_to_clean: Dict[int, int] = {}
    code_text_by_orig: Dict[int, str] = {}

    for idx, line in enumerate(lines, start=1):
        i = 0
        out = ""
        # strip comments from this line
        while i < len(line):
            two = line[i:i+2]

            if not in_block and two == "/*":
                in_block = True
                i += 2
                continue

            if in_block:
                end = line.find("*/", i)
                if end == -1:
                    # rest of this line is inside block comment
                    i = len(line)
                    continue
                else:
                    in_block = False
                    i = end + 2
                    continue

            # not in block
            if two == "//":
                break

            out += line[i]
            i += 1

        code_text_by_orig[idx] = out

        # remove empty lines
        if out.strip() == "":
            continue

        cleaned_lines.append(out.rstrip())
        orig_to_clean[idx] = len(cleaned_lines)

    cleaned = "\n".join(cleaned_lines).strip()
    return cleaned, orig_to_clean, code_text_by_orig


def parse_vulnerabilities(
    raw_text: str,
    code_text_by_orig: Dict[int, str],
    fallback_category: Optional[str] = None
) -> List[Tuple[int, str]]:
    """
    Returns list of (vulnerable_statement_original_line, category_lowercase)

    Primary method:
      - Detect marker line: // <yes> <report> CATEGORY
      - If marker is inline with code: vulnerable line is same line
      - Else vulnerable line is the next line that contains code (after comment stripping)

    Fallback:
      - If no markers found, use @vulnerable_at_lines and fallback_category (usually folder name)
    """
    lines = raw_text.splitlines()
    pending_categories: List[str] = []
    found_any_marker = False
    vulns: List[Tuple[int, str]] = []

    for idx, line in enumerate(lines, start=1):
        markers = VULN_MARKER_RE.findall(line)
        if markers:
            found_any_marker = True
            code_part = code_text_by_orig.get(idx, "")
            # If there is code before the // marker, it's inline
            if code_part.strip():
                for cat in markers:
                    vulns.append((idx, cat.lower()))
            else:
                for cat in markers:
                    pending_categories.append(cat.lower())

        # assign pending markers to the next code line
        if pending_categories and code_text_by_orig.get(idx, "").strip():
            for cat in pending_categories:
                vulns.append((idx, cat))
            pending_categories.clear()

    if found_any_marker:
        return vulns

    # Fallback: @vulnerable_at_lines with category from folder (if available)
    m = VULN_AT_LINES_RE.search(raw_text)
    if m and fallback_category:
        # supports "21" or "21, 45  ,  90"
        nums = re.findall(r"\d+", m.group(1))
        for n in nums:
            vulns.append((int(n), fallback_category.lower()))

    return vulns


def aggregate_vulnerabilities(remapped_vulns: List[Tuple[int, str]]) -> List[Dict]:
    """
    Convert list of (clean_line, category) to your JSON structure:
      [{"lines":[...], "category":"reentrancy"}, ...]
    """
    by_cat: Dict[str, set] = {}
    for line_no, cat in remapped_vulns:
        by_cat.setdefault(cat, set()).add(int(line_no))

    out = []
    for cat in sorted(by_cat.keys()):
        out.append({
            "lines": sorted(by_cat[cat]),
            "category": cat
        })
    return out


if __name__ == "__main__":
    input_dir = "dataset"
    output_dir = "dataset_clean"
    index_json_path = os.path.join(output_dir, "dataset_index.json")

    records: Dict[str, Dict] = {} # json records to build

    for root, _, files in os.walk(input_dir):
        for filename in files:
            if not filename.endswith(".sol"):
                continue

            filepath = os.path.join(root, filename)

            with open(filepath, "r", encoding="utf8") as f:
                raw = f.read()

            # category fallback from folder name: dataset/<category>/...
            rel_root = os.path.relpath(root, input_dir)
            rel_root_norm = "" if rel_root == "." else rel_root
            first_dir = rel_root_norm.split(os.sep)[0] if rel_root_norm else None
            fallback_category = first_dir

            # Build cleaned content + mapping BEFORE we lose line info
            cleaned_content, orig_to_clean, code_text_by_orig = strip_comments_build_mapping(raw)

            # Parse vulnerabilities in ORIGINAL lines, then remap to CLEANED lines
            orig_vulns = parse_vulnerabilities(raw, code_text_by_orig, fallback_category=fallback_category)

            remapped: List[Tuple[int, str]] = []
            for orig_line, cat in orig_vulns:
                clean_line = orig_to_clean.get(orig_line)
                if clean_line is not None:
                    remapped.append((clean_line, cat))
                else:
                    # If the vulnerable statement line got fully removed (rare),
                    # try mapping to the next surviving code line.
                    nxt = orig_line + 1
                    while nxt <= max(orig_to_clean.keys(), default=0) and nxt not in orig_to_clean:
                        nxt += 1
                    if nxt in orig_to_clean:
                        remapped.append((orig_to_clean[nxt], cat))
                    # else: drop (nothing to map)

            # Write cleaned file to dataset_clean mirroring folder structure
            new_dir = os.path.join(output_dir, rel_root_norm) if rel_root_norm else output_dir
            os.makedirs(new_dir, exist_ok=True)
            new_filepath = os.path.join(new_dir, filename)
            with open(new_filepath, "w", encoding="utf8") as f:
                f.write(cleaned_content)

            # Build record
            record = {
                "name": filename,
                "path": os.path.join(input_dir, rel_root_norm, filename).replace("\\", "/"),
                "pragma": extract_pragma_version(raw),
                "source": extract_source(raw),
                "vulnerabilities": aggregate_vulnerabilities(remapped),
            }
            records[filename] = record

    os.makedirs(output_dir, exist_ok=True)
    with open(index_json_path, "w", encoding="utf8") as f:
        json.dump(records, f, indent=4)

    print(f"Saved {len(records)} records to: {index_json_path}")
