#!/usr/bin/env python3
"""
Lattice-Map: PQC Audit Scanner
Scans any codebase (Python, JS/TS, Java, Go, Rust, C/C++, Ruby, PHP, Swift, Kotlin)
for quantum-vulnerable cryptographic algorithms and generates data.json.

Usage:
    python lattice_map_scanner.py [target_directory] [--output data.json]
"""

import os
import re
import json
import sys
import argparse
from pathlib import Path
from collections import defaultdict

# ─── Supported file extensions ────────────────────────────────────────────────

SUPPORTED_EXTENSIONS = {
    # Python
    '.py',
    # JavaScript / TypeScript
    '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
    # Java / Kotlin / Scala
    '.java', '.kt', '.kts', '.scala',
    # Go
    '.go',
    # Rust
    '.rs',
    # C / C++
    '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
    # Ruby
    '.rb',
    # PHP
    '.php',
    # Swift
    '.swift',
    # C#
    '.cs',
    # Elixir / Erlang
    '.ex', '.exs', '.erl',
    # Shell scripts that may call crypto tools
    '.sh', '.bash',
    # Config files with crypto refs
    '.yaml', '.yml', '.toml', '.json', '.env',
}

# ─── Algorithm Signature Definitions ─────────────────────────────────────────

CRITICAL_PATTERNS = {
    "RSA":            re.compile(r'\b(RSA|rsa|PKCS1|pkcs1|generateRSA|KeyFactory.*RSA|RSACryptoServiceProvider|Crypto\.PublicKey\.RSA|openssl.*rsa|rsa\.generate)\b'),
    "DSA":            re.compile(r'\b(DSA|dsa|DSACryptoServiceProvider|Crypto\.PublicKey\.DSA|KeyPairGenerator.*DSA)\b'),
    "Diffie-Hellman": re.compile(r'\b(DHE?|DiffieHellman|diffie.hellman|DHParameters|crypto\.createDiffieHellman|javax\.crypto.*DH)\b'),
    "ECDSA":          re.compile(r'\b(ECDSA|ecdsa|EC\.ECDSA|EllipticCurve|SECP256|SECP384|SECP521|brainpool|prime256v1|ECDSACryptoServiceProvider|crypto\.createECDH)\b'),
    "SHA-1":          re.compile(r'\b(SHA1|sha1|SHA\-1|SHA_1|MessageDigest.*SHA.1|hashlib\.sha1|crypto\.createHash.*sha1|DigestAlgorithm.*SHA1|openssl.*sha1)\b', re.IGNORECASE),
    "MD5":            re.compile(r'\b(MD5|md5|hashlib\.md5|MessageDigest.*MD5|crypto\.createHash.*md5|MD5CryptoServiceProvider|openssl.*md5)\b', re.IGNORECASE),
    "AES-CBC":        re.compile(r'\b(AES.{0,10}CBC|CBC.{0,10}AES|modes\.CBC|IvParameterSpec|CipherMode\.CBC|aes-\d+-cbc|EVP.*CBC)\b'),
    "RC4":            re.compile(r'\b(RC4|ARC4|arc4|ARCFOUR|rc4|CipherSuite.*RC4)\b'),
    "3DES":           re.compile(r'\b(TripleDES|3DES|DES3|Triple_DES|DESedeKeySpec|des-ede|DESede|TripleDESCryptoServiceProvider)\b'),
    "DES":            re.compile(r'(?<!\w)(DES|des)(?!\w|3|ede|\-ede)'),
}

SECURE_PATTERNS = {
    "ML-KEM (Kyber)":      re.compile(r'\b(ML.KEM|Kyber|kyber|mlkem|CRYSTALS.Kyber|pqcrypto.*kem|liboqs.*kem|kyber\d+)\b'),
    "ML-DSA (Dilithium)":  re.compile(r'\b(ML.DSA|Dilithium|dilithium|mldsa|CRYSTALS.Dilithium|pqcrypto.*sign)\b'),
    "SLH-DSA (SPHINCS+)":  re.compile(r'\b(SLH.DSA|SPHINCS|sphincs|slhdsa)\b'),
    "FALCON":               re.compile(r'\b(FALCON|falcon|pqcrypto.*falcon)\b'),
    "AES-GCM":              re.compile(r'\b(AES.{0,10}GCM|GCM.{0,10}AES|modes\.GCM|AESGCM|GCMParameterSpec|aes-\d+-gcm|AesGcm|ChaCha20Poly1305)\b'),
    "SHA-3":                re.compile(r'\b(SHA3|sha3|SHA\.3|SHA_3|Keccak|keccak|hashlib\.sha3|MessageDigest.*SHA.3)\b'),
    "SHA-256":              re.compile(r'\b(SHA256|sha256|SHA.256|hashlib\.sha256|MessageDigest.*SHA.256|crypto\.createHash.*sha256)\b'),
    "SHA-512":              re.compile(r'\b(SHA512|sha512|SHA.512|hashlib\.sha512|MessageDigest.*SHA.512)\b'),
    "ChaCha20":             re.compile(r'\b(ChaCha20|chacha20|chacha)\b'),
}

# Language-aware import patterns
IMPORT_PATTERNS = [
    # Python: from X import Y / import X
    re.compile(r'^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))', re.MULTILINE),
    # JS/TS: import ... from 'x' / require('x')
    re.compile(r"""(?:import\s+.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))""", re.MULTILINE),
    # Java/Kotlin: import com.example.Foo
    re.compile(r'^\s*import\s+([\w.]+);', re.MULTILINE),
    # Go: import "pkg" or import ("pkg")
    re.compile(r'^\s*import\s+(?:"([^"]+)"|[\w]+\s+"([^"]+)")', re.MULTILINE),
    # Rust: use crate::module
    re.compile(r'^\s*use\s+([\w:]+)', re.MULTILINE),
    # Ruby: require 'gem'
    re.compile(r"""^\s*require(?:_relative)?\s+['"]([^'"]+)['"]""", re.MULTILINE),
    # PHP: use Namespace\Class
    re.compile(r'^\s*use\s+([\w\\]+);', re.MULTILINE),
    # C#: using Namespace;
    re.compile(r'^\s*using\s+([\w.]+);', re.MULTILINE),
]

SKIP_DIRS = {
    '.venv', 'venv', '__pycache__', '.git', '.tox', 'node_modules',
    '.mypy_cache', 'dist', 'build', '.eggs', '.next', 'target',
    'vendor', 'Pods', '.gradle', '.idea', '.vs', 'obj', 'bin',
    'coverage', '.nyc_output', 'out', '.parcel-cache',
}

MITIGATION_MAP = {
    "RSA":            "Replace with ML-KEM-768 (key encapsulation) or ML-DSA-65 (signatures) per FIPS 203/204.",
    "DSA":            "Replace with ML-DSA-65 (Dilithium) per NIST FIPS 204.",
    "Diffie-Hellman": "Replace key exchange with ML-KEM-768 (Kyber) per NIST FIPS 203.",
    "ECDSA":          "Replace with ML-DSA-65 or SLH-DSA-128s per NIST FIPS 204/205.",
    "SHA-1":          "Replace with SHA-256 or SHA-3-256 immediately. SHA-1 is fully broken.",
    "MD5":            "Replace with SHA-256 or BLAKE2b. MD5 is cryptographically broken.",
    "AES-CBC":        "Replace with AES-256-GCM or ChaCha20-Poly1305 for authenticated encryption.",
    "RC4":            "Remove RC4 immediately. Use ChaCha20-Poly1305 instead.",
    "3DES":           "Replace with AES-256-GCM. 3DES is deprecated by NIST (SP 800-131A).",
    "DES":            "Remove DES immediately. It provides ~56-bit security, trivially broken.",
}

RISK_WEIGHTS = {
    "RSA": 10, "DSA": 9, "Diffie-Hellman": 9, "ECDSA": 8,
    "SHA-1": 7, "MD5": 7, "AES-CBC": 5, "RC4": 10, "3DES": 6, "DES": 10,
}

# ─── Scanner ──────────────────────────────────────────────────────────────────

def scan_file(filepath: Path) -> dict:
    try:
        source = filepath.read_text(encoding='utf-8', errors='replace')
    except (PermissionError, OSError):
        return None

    critical_found = {}
    secure_found = []

    for algo, pattern in CRITICAL_PATTERNS.items():
        matches = pattern.findall(source)
        if matches:
            flat = []
            for m in matches:
                if isinstance(m, tuple):
                    flat.extend(x for x in m if x)
                else:
                    flat.append(m)
            critical_found[algo] = list(set(flat))[:5]

    for algo, pattern in SECURE_PATTERNS.items():
        if pattern.search(source):
            secure_found.append(algo)

    # Extract imports across all language styles
    imports = []
    for pat in IMPORT_PATTERNS:
        for match in pat.finditer(source):
            for group in match.groups():
                if group:
                    # Take root module name (before / or . or ::)
                    root = re.split(r'[/.:]+', group.strip())[0]
                    if root and len(root) > 1 and not root.startswith('@'):
                        imports.append(root)
    imports = list(set(imports))

    return {
        "critical": critical_found,
        "secure": secure_found,
        "imports": imports,
        "size": filepath.stat().st_size,
        "ext": filepath.suffix.lower(),
    }


def compute_risk_score(critical: dict) -> float:
    if not critical:
        return 0.0
    scores = [RISK_WEIGHTS.get(algo, 5) for algo in critical]
    return min(10.0, sum(scores) / len(scores) + (len(scores) - 1) * 0.5)


def scan_directory(target: str) -> dict:
    target_path = Path(target).resolve()
    raw = {}

    print(f"\n🔍 Scanning: {target_path}\n")

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.')]

        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue

            rel_path = str(fpath.relative_to(target_path))
            # Use path as module ID (forward slashes, no extension)
            module_name = rel_path.replace('\\', '/').rsplit('.', 1)[0]
            short_name = fpath.stem

            result = scan_file(fpath)
            if result is None:
                continue

            raw[module_name] = {
                **result,
                "path": rel_path.replace('\\', '/'),
                "abs_path": str(fpath),
                "short_name": short_name,
            }
            status = "🔴" if result["critical"] else ("🟢" if result["secure"] else "⚪")
            print(f"  {status}  {rel_path}")

    return raw


def resolve_imports(raw: dict) -> dict:
    short_lookup = {}
    for mod_name, data in raw.items():
        short = data["short_name"]
        short_lookup.setdefault(short, []).append(mod_name)

    graph = defaultdict(set)

    for mod_name, data in raw.items():
        for imp in data["imports"]:
            if imp in raw:
                graph[mod_name].add(imp)
            elif imp in short_lookup:
                for candidate in short_lookup[imp]:
                    if candidate != mod_name:
                        graph[mod_name].add(candidate)

    return graph


def propagate_risk(raw: dict, graph: dict) -> dict:
    colors = {}
    for mod, data in raw.items():
        if data["critical"]:
            colors[mod] = "red"
        elif data["secure"]:
            colors[mod] = "green"
        else:
            colors[mod] = "grey"

    reverse = defaultdict(set)
    for src, targets in graph.items():
        for tgt in targets:
            reverse[tgt].add(src)

    visited = set()
    queue = [m for m, c in colors.items() if c == "red"]

    while queue:
        current = queue.pop()
        if current in visited:
            continue
        visited.add(current)
        for parent in reverse[current]:
            if colors.get(parent) not in ("red",):
                if colors.get(parent) != "yellow":
                    colors[parent] = "yellow"
                    queue.append(parent)

    return colors


def build_json(raw: dict, graph: dict, colors: dict) -> dict:
    nodes = []
    for mod, data in raw.items():
        color = colors.get(mod, "grey")
        risk_score = round(compute_risk_score(data["critical"]), 1)

        crypto_found = []
        for algo, matches in data["critical"].items():
            crypto_found.append({
                "algorithm": algo,
                "severity": "CRITICAL",
                "matches": matches,
                "mitigation": MITIGATION_MAP.get(algo, "Migrate to NIST PQC standard."),
            })
        for algo in data["secure"]:
            crypto_found.append({
                "algorithm": algo,
                "severity": "SECURE",
                "matches": [],
                "mitigation": "✅ Already using PQC-safe algorithm.",
            })

        nodes.append({
            "id": mod,
            "label": data["path"],
            "color": color,
            "risk_score": risk_score if color == "red" else (5.0 if color == "yellow" else 0.0),
            "size": data["size"],
            "ext": data.get("ext", ""),
            "crypto_found": crypto_found,
            "imports": list(graph.get(mod, [])),
        })

    links = []
    seen_links = set()
    for src, targets in graph.items():
        for tgt in targets:
            key = (src, tgt)
            if key not in seen_links:
                seen_links.add(key)
                links.append({"source": src, "target": tgt})

    total = len(nodes)
    red_count = sum(1 for n in nodes if n["color"] == "red")
    yellow_count = sum(1 for n in nodes if n["color"] == "yellow")
    green_count = sum(1 for n in nodes if n["color"] == "green")
    grey_count = sum(1 for n in nodes if n["color"] == "grey")
    at_risk = red_count + yellow_count
    debt_score = round((at_risk / total * 100) if total > 0 else 0, 1)

    return {
        "meta": {
            "scanned_dir": "",
            "total_files": total,
            "red": red_count,
            "yellow": yellow_count,
            "green": green_count,
            "grey": grey_count,
            "quantum_debt_score": debt_score,
            "migrated": green_count,
        },
        "nodes": nodes,
        "links": links,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Lattice-Map PQC Scanner — detect Quantum Debt in any codebase"
    )
    parser.add_argument("target", nargs="?", default=".", help="Directory to scan (default: current dir)")
    parser.add_argument("--output", default="data.json", help="Output JSON file path")
    args = parser.parse_args()

    target = args.target
    if not os.path.isdir(target):
        print(f"❌ Error: '{target}' is not a valid directory.", file=sys.stderr)
        sys.exit(1)

    raw = scan_directory(target)
    if not raw:
        print("⚠️  No supported source files found.")
        print(f"   Supported extensions: {', '.join(sorted(SUPPORTED_EXTENSIONS))}")
        sys.exit(0)

    graph = resolve_imports(raw)
    colors = propagate_risk(raw, graph)
    output = build_json(raw, graph, colors)
    output["meta"]["scanned_dir"] = str(Path(target).resolve())

    out_path = Path(args.output)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)

    m = output["meta"]
    exts = set(d.get("ext","") for d in raw.values() if d.get("ext"))
    print(f"""
╔══════════════════════════════════════════╗
║        LATTICE-MAP SCAN COMPLETE         ║
╠══════════════════════════════════════════╣
║  Files scanned   : {m['total_files']:<22}║
║  Languages found : {', '.join(sorted(exts)):<22}║
║  🔴 Critical     : {m['red']:<22}║
║  🟡 At Risk      : {m['yellow']:<22}║
║  🟢 Secure (PQC) : {m['green']:<22}║
║  ⚪ No Crypto    : {m['grey']:<22}║
╠══════════════════════════════════════════╣
║  Quantum Debt Score : {m['quantum_debt_score']:<19}%║
║  Output file        : {str(out_path):<19}║
╚══════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
