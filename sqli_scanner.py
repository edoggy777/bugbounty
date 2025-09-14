#!/usr/bin/env python3
"""
Enhanced SQL Injection Scanner for Android APK Analysis
Significantly improved heuristics to reduce false positives while catching real vulnerabilities.

USAGE EXAMPLES:

Basic scan of decompiled APK:
  python3 sqli_scanner.py ./jadx_output

High-confidence findings only:
  python3 sqli_scanner.py ./jadx_output --min-confidence 0.7

Critical and high severity only:
  python3 sqli_scanner.py ./jadx_output --severity high

Custom output with more context:
  python3 sqli_scanner.py ./jadx_output --output detailed_report.json --context 5

Verbose scan with medium+ findings:
  python3 sqli_scanner.py ./jadx_output --verbose --severity medium --min-confidence 0.4

WORKFLOW TIPS:

1. Start with high confidence to find obvious issues:
   python3 sqli_scanner.py ./app --min-confidence 0.8

2. Review critical/high findings first, then lower thresholds:
   python3 sqli_scanner.py ./app --severity high

3. For comprehensive audit, use lower thresholds:
   python3 sqli_scanner.py ./app --min-confidence 0.3 --severity low

4. Focus on specific file types by filtering the output directory

UNDERSTANDING THE OUTPUT:

- Confidence (0.0-1.0): Higher = more likely to be a real vulnerability
- Severity: CRITICAL > HIGH > MEDIUM > LOW > INFO
- User input sources: Shows where dangerous data might originate
- Context lines: Code surrounding the potential vulnerability

The scanner looks for:
- String concatenation in SQL queries with user input
- Missing parameterized queries (no '?' placeholders) 
- String.format() with SQL (highly dangerous)
- PreparedStatement misuse
- ContentResolver injection points

Prerequisites:
- Decompiled APK source (use jadx, apktool, or similar)
- Python 3.7+
"""
from __future__ import annotations
import re, os, json, sys, datetime
from pathlib import Path
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Finding:
    file_path: str
    line_number: int
    severity: Severity
    pattern_type: str
    description: str
    code_snippet: str
    context_lines: List[Dict[str, Any]]
    confidence: float
    user_input_sources: List[str]

TEXT_EXTS = {".java", ".kt", ".kts", ".smali"}
IGNORE_DIRS = {".git", "build", "node_modules", "__pycache__", "libs", "res", "assets"}

# User input sources ranked by risk
HIGH_RISK_SOURCES = {
    "getStringExtra", "getIntent().getStringExtra", "getQueryParameter", 
    "getParameter", "getText().toString()", "getEditText", "request.getParameter",
    "bundle.getString", "intent.getStringExtra", "uri.getQueryParameter"
}

MEDIUM_RISK_SOURCES = {
    "getString", "preferences.getString", "sharedPrefs.getString", 
    "cursor.getString", "getColumnString"
}

# Safe patterns that shouldn't trigger alerts
SAFE_PATTERNS = [
    re.compile(r'["\'](?:CREATE TABLE|DROP TABLE|ALTER TABLE)[^"\']*["\']', re.I),
    re.compile(r'["\'](?:PRAGMA |\.db|\.sqlite)[^"\']*["\']', re.I),
    re.compile(r'["\'][^"\']*["\']\s*\+\s*["\'][^"\']*["\']'),  # String literal + String literal
    re.compile(r'LOG_TAG|TAG|DEBUG|"TAG"', re.I),
    re.compile(r'System\.out\.print|Log\.[deiw]', re.I),
]

# Table/column name patterns (usually safe)
SCHEMA_PATTERNS = [
    re.compile(r'\b(?:TABLE_|COL_|COLUMN_|DB_)[A-Z_]+\b'),
    re.compile(r'\b[A-Z_]{3,}(?:_TABLE|_COL|_COLUMN)\b'),
]

class SQLiScanner:
    def __init__(self, context_lines: int = 2, max_file_size: int = 1_000_000):
        self.context_lines = context_lines
        self.max_file_size = max_file_size
        self.findings = []
        
    def is_safe_concatenation(self, code_block: str) -> bool:
        """Check if concatenation appears to be safe (constants, schema names, etc.)"""
        for pattern in SAFE_PATTERNS:
            if pattern.search(code_block):
                return True
        return False
    
    def is_schema_reference(self, variable: str) -> bool:
        """Check if variable appears to be a table/column name constant"""
        for pattern in SCHEMA_PATTERNS:
            if pattern.match(variable):
                return True
        return variable.isupper() and ('_' in variable)
    
    def extract_user_input_sources(self, content: str, line_start: int, line_end: int) -> List[str]:
        """Find user input sources within the context of a potential vulnerability"""
        lines = content.splitlines()
        context_start = max(0, line_start - 10)
        context_end = min(len(lines), line_end + 10)
        context = '\n'.join(lines[context_start:context_end])
        
        sources = []
        for source in HIGH_RISK_SOURCES | MEDIUM_RISK_SOURCES:
            if source.lower() in context.lower():
                sources.append(source)
        return sources
    
    def calculate_confidence(self, pattern_type: str, user_sources: List[str], code_snippet: str) -> float:
        """Calculate confidence score based on various factors"""
        base_confidence = 0.5
        
        # Boost for high-risk user input sources
        if any(src in HIGH_RISK_SOURCES for src in user_sources):
            base_confidence += 0.3
        elif any(src in MEDIUM_RISK_SOURCES for src in user_sources):
            base_confidence += 0.1
            
        # Boost for dangerous SQL operations
        if re.search(r'\b(?:DELETE|DROP|INSERT|UPDATE|REPLACE)\b', code_snippet, re.I):
            base_confidence += 0.2
        
        # Reduce for parameterized queries
        if '?' in code_snippet and 'selectionArgs' in code_snippet:
            base_confidence -= 0.4
            
        # Reduce for safe-looking patterns
        if self.is_safe_concatenation(code_snippet):
            base_confidence -= 0.3
            
        return min(1.0, max(0.1, base_confidence))
    
    def scan_rawquery_execsql(self, content: str) -> List[Finding]:
        """Scan for dangerous rawQuery/execSQL patterns"""
        findings = []
        
        # Pattern for concatenated SQL in rawQuery/execSQL
        pattern = re.compile(
            r'\b((?:db\.|database\.)?(?:rawQuery|execSQL|rawQueryWithFactory))\s*\(\s*'
            r'([^,\)]+\+[^,\)]*)',
            re.I | re.S
        )
        
        for match in pattern.finditer(content):
            method = match.group(1)
            sql_expr = match.group(2)
            
            # Skip if it looks safe
            if self.is_safe_concatenation(sql_expr):
                continue
                
            line_info = self._get_line_info(content, match.start())
            user_sources = self.extract_user_input_sources(content, line_info['line'] - 5, line_info['line'] + 5)
            
            # Only flag if we found potential user input sources
            if user_sources or re.search(r'\b(?:getStringExtra|getText|getParameter)\b', sql_expr, re.I):
                confidence = self.calculate_confidence("sql_concatenation", user_sources, match.group(0))
                
                if confidence > 0.3:  # Minimum threshold
                    severity = Severity.CRITICAL if confidence > 0.7 else Severity.HIGH
                    
                    findings.append(Finding(
                        file_path="",  # Will be set by caller
                        line_number=line_info['line'],
                        severity=severity,
                        pattern_type="dangerous_sql_concatenation",
                        description=f"Potential SQL injection in {method} with string concatenation",
                        code_snippet=match.group(0)[:200],
                        context_lines=line_info['context'],
                        confidence=confidence,
                        user_input_sources=user_sources
                    ))
        
        return findings
    
    def scan_query_methods(self, content: str) -> List[Finding]:
        """Scan for dangerous query() method patterns"""
        findings = []
        
        # Look for db.query with concatenated selection
        pattern = re.compile(
            r'\b(?:db\.|database\.)?query\s*\([^,]*,\s*'
            r'([^,]*\+[^,]*),',
            re.I | re.S
        )
        
        for match in pattern.finditer(content):
            selection = match.group(1).strip()
            
            # Skip if using proper selectionArgs pattern
            full_match = match.group(0)
            if 'selectionArgs' in full_match and '?' in selection:
                continue
                
            if self.is_safe_concatenation(selection):
                continue
                
            line_info = self._get_line_info(content, match.start())
            user_sources = self.extract_user_input_sources(content, line_info['line'] - 5, line_info['line'] + 5)
            
            confidence = self.calculate_confidence("query_selection", user_sources, match.group(0))
            
            if confidence > 0.4:
                severity = Severity.HIGH if confidence > 0.6 else Severity.MEDIUM
                
                findings.append(Finding(
                    file_path="",
                    line_number=line_info['line'],
                    severity=severity,
                    pattern_type="query_selection_injection",
                    description="Potential SQL injection in query() selection parameter",
                    code_snippet=match.group(0)[:200],
                    context_lines=line_info['context'],
                    confidence=confidence,
                    user_input_sources=user_sources
                ))
        
        return findings
    
    def scan_string_format_sql(self, content: str) -> List[Finding]:
        """Scan for String.format with SQL"""
        findings = []
        
        pattern = re.compile(
            r'\b(?:rawQuery|execSQL|query)\s*\(\s*String\.format\s*\(\s*'
            r'["\']([^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*)["\']',
            re.I | re.S
        )
        
        for match in pattern.finditer(content):
            sql_template = match.group(1)
            
            line_info = self._get_line_info(content, match.start())
            user_sources = self.extract_user_input_sources(content, line_info['line'] - 5, line_info['line'] + 5)
            
            # String.format with SQL is almost always dangerous
            confidence = 0.8
            if user_sources:
                confidence = 0.9
                
            findings.append(Finding(
                file_path="",
                line_number=line_info['line'],
                severity=Severity.CRITICAL,
                pattern_type="string_format_sql",
                description="SQL injection via String.format - highly dangerous",
                code_snippet=match.group(0)[:200],
                context_lines=line_info['context'],
                confidence=confidence,
                user_input_sources=user_sources
            ))
        
        return findings
    
    def scan_content_resolver(self, content: str) -> List[Finding]:
        """Scan for ContentResolver query issues"""
        findings = []
        
        pattern = re.compile(
            r'\bContentResolver\.query\s*\([^,]*,\s*'
            r'([^,]*\+[^,]*),',
            re.I | re.S
        )
        
        for match in pattern.finditer(content):
            line_info = self._get_line_info(content, match.start())
            user_sources = self.extract_user_input_sources(content, line_info['line'] - 5, line_info['line'] + 5)
            
            confidence = self.calculate_confidence("content_resolver", user_sources, match.group(0))
            
            if confidence > 0.3:
                severity = Severity.MEDIUM if confidence > 0.5 else Severity.LOW
                
                findings.append(Finding(
                    file_path="",
                    line_number=line_info['line'],
                    severity=severity,
                    pattern_type="content_resolver_injection",
                    description="Potential injection in ContentResolver.query",
                    code_snippet=match.group(0)[:200],
                    context_lines=line_info['context'],
                    confidence=confidence,
                    user_input_sources=user_sources
                ))
        
        return findings
    
    def scan_prepared_statement_misuse(self, content: str) -> List[Finding]:
        """Look for misuse of prepared statements"""
        findings = []
        
        # PreparedStatement with concatenation (should use parameters instead)
        pattern = re.compile(
            r'\bcompileStatement\s*\(\s*[^)]*\+[^)]*\)',
            re.I | re.S
        )
        
        for match in pattern.finditer(content):
            if self.is_safe_concatenation(match.group(0)):
                continue
                
            line_info = self._get_line_info(content, match.start())
            user_sources = self.extract_user_input_sources(content, line_info['line'] - 5, line_info['line'] + 5)
            
            confidence = self.calculate_confidence("prepared_statement", user_sources, match.group(0))
            
            if confidence > 0.3:
                findings.append(Finding(
                    file_path="",
                    line_number=line_info['line'],
                    severity=Severity.HIGH,
                    pattern_type="prepared_statement_misuse",
                    description="PreparedStatement with concatenation - should use bindString/bindLong",
                    code_snippet=match.group(0)[:200],
                    context_lines=line_info['context'],
                    confidence=confidence,
                    user_input_sources=user_sources
                ))
        
        return findings
    
    def _get_line_info(self, content: str, char_pos: int) -> Dict[str, Any]:
        """Get line number and context for a character position"""
        lines = content.splitlines()
        char_count = 0
        line_num = 1
        
        for i, line in enumerate(lines):
            if char_count <= char_pos <= char_count + len(line):
                line_num = i + 1
                break
            char_count += len(line) + 1  # +1 for newline
        
        start_line = max(0, line_num - 1 - self.context_lines)
        end_line = min(len(lines), line_num + self.context_lines)
        
        context = []
        for i in range(start_line, end_line):
            context.append({
                "line_no": i + 1,
                "text": lines[i],
                "is_match": i + 1 == line_num
            })
        
        return {"line": line_num, "context": context}
    
    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file for SQL injection vulnerabilities"""
        try:
            if file_path.stat().st_size > self.max_file_size:
                return []
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return []
        
        findings = []
        
        # Run all scan methods
        findings.extend(self.scan_rawquery_execsql(content))
        findings.extend(self.scan_query_methods(content))
        findings.extend(self.scan_string_format_sql(content))
        findings.extend(self.scan_content_resolver(content))
        findings.extend(self.scan_prepared_statement_misuse(content))
        
        # Set file path for all findings
        for finding in findings:
            finding.file_path = str(file_path)
        
        return findings
    
    def scan_directory(self, root_path: Path) -> List[Finding]:
        """Scan a directory tree for SQL injection vulnerabilities"""
        all_findings = []
        
        for dirpath, dirnames, filenames in os.walk(root_path):
            # Skip ignored directories
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
            
            for filename in filenames:
                file_path = Path(dirpath) / filename
                
                if file_path.suffix.lower() in TEXT_EXTS:
                    findings = self.scan_file(file_path)
                    all_findings.extend(findings)
        
        return all_findings

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enhanced SQL Injection Scanner for Android APK Analysis"
    )
    parser.add_argument("path", help="Root directory to scan")
    parser.add_argument("--output", "-o", default="sqli_report.json", 
                       help="Output report file")
    parser.add_argument("--context", "-c", type=int, default=2,
                       help="Lines of context to include")
    parser.add_argument("--min-confidence", "-m", type=float, default=0.3,
                       help="Minimum confidence threshold (0.0-1.0)")
    parser.add_argument("--severity", "-s", 
                       choices=[s.value for s in Severity],
                       help="Minimum severity level to report")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output")
    
    args = parser.parse_args()
    
    root_path = Path(args.path)
    if not root_path.exists():
        print(f"Error: Path does not exist: {root_path}", file=sys.stderr)
        sys.exit(1)
    
    scanner = SQLiScanner(context_lines=args.context)
    
    if args.verbose:
        print(f"Scanning {root_path}...")
    
    findings = scanner.scan_directory(root_path)
    
    # Filter by confidence and severity
    filtered_findings = []
    severity_order = {s: i for i, s in enumerate([Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])}
    min_severity_level = severity_order.get(Severity(args.severity), 0) if args.severity else 0
    
    for finding in findings:
        if (finding.confidence >= args.min_confidence and
            severity_order[finding.severity] >= min_severity_level):
            filtered_findings.append(finding)
    
    # Sort by severity (critical first) then by confidence
    filtered_findings.sort(
        key=lambda f: (severity_order[f.severity], f.confidence),
        reverse=True
    )
    
    # Generate report
    report = {
        "scan_info": {
            "root_path": str(root_path),
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "total_findings": len(findings),
            "filtered_findings": len(filtered_findings),
            "min_confidence": args.min_confidence,
            "min_severity": args.severity or "info"
        },
        "findings": [
            {
                "file": f.file_path,
                "line": f.line_number,
                "severity": f.severity.value,
                "type": f.pattern_type,
                "description": f.description,
                "confidence": round(f.confidence, 2),
                "user_input_sources": f.user_input_sources,
                "code_snippet": f.code_snippet,
                "context": f.context_lines
            }
            for f in filtered_findings
        ],
        "summary": {
            severity.value: len([f for f in filtered_findings if f.severity == severity])
            for severity in Severity
        }
    }
    
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    print(f"Scan complete!")
    print(f"Total findings: {len(findings)}")
    print(f"High-confidence findings: {len(filtered_findings)}")
    print(f"Critical: {report['summary']['critical']}")
    print(f"High: {report['summary']['high']}")
    print(f"Medium: {report['summary']['medium']}")
    print(f"Report saved to: {args.output}")

if __name__ == "__main__":
    main()
