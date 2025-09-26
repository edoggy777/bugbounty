#!/usr/bin/env python3
"""
Professional Android Security Scanner
A static analysis tool for identifying high-confidence security vulnerabilities
in decompiled Android applications with minimal false positives.

Usage: python3 android_security_scanner.py <path_to_decompiled_code>
Author: Security Research Team
License: MIT
"""

import os
import re
import argparse
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class RiskLevel(Enum):
    HIGH = "HIGH"
    MODERATE = "MODERATE"

@dataclass
class SecurityFinding:
    file_path: str
    line_number: int
    line_content: str
    pattern_id: str
    risk_level: RiskLevel
    description: str
    impact: str
    recommendation: str
    confidence: float
    context: List[str]
    method_name: Optional[str] = None

class AndroidSecurityScanner:
    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.scanned_files = 0
        self.processed_hashes: Set[str] = set()  # Prevent duplicate findings
        
        # High-confidence security patterns with context requirements
        self.security_patterns = {
            # HIGH RISK - Direct code execution
            "runtime_exec_dynamic": {
                "pattern": r"Runtime\.getRuntime\(\)\.exec\s*\(\s*([^)]*(?:getString|getIntent|input|param|arg)[^)]*)\)",
                "risk": RiskLevel.HIGH,
                "description": "Dynamic command execution with external input",
                "impact": "Arbitrary command execution, potential RCE",
                "recommendation": "Validate and sanitize all inputs, use parameterized execution, avoid Runtime.exec with user input",
                "requires_context": ["input", "string", "intent", "param"]
            },
            
            "process_builder_dynamic": {
                "pattern": r"new\s+ProcessBuilder\s*\([^)]*(?:getString|getIntent|input|param|Bundle)[^)]*\)",
                "risk": RiskLevel.HIGH,
                "description": "ProcessBuilder with dynamic arguments",
                "impact": "Command injection, arbitrary process execution",
                "recommendation": "Use fixed command arguments, validate inputs, consider alternatives to ProcessBuilder",
                "requires_context": ["input", "bundle", "intent"]
            },
            
            "reflection_dynamic_class": {
                "pattern": r"Class\.forName\s*\(\s*([^)]*(?:getString|getIntent|input|Bundle|Extra)[^)]*)\)",
                "risk": RiskLevel.HIGH,
                "description": "Dynamic class loading with external input",
                "impact": "Arbitrary class loading, potential code execution",
                "recommendation": "Whitelist allowed classes, validate class names, use static imports where possible",
                "requires_context": ["input", "string", "extra", "bundle"]
            },
            
            "method_invoke_untrusted": {
                "pattern": r"Method\.invoke\s*\([^,]*,\s*[^)]*(?:getString|getIntent|Bundle|input)[^)]*\)",
                "risk": RiskLevel.HIGH,
                "description": "Dynamic method invocation with external parameters",
                "impact": "Arbitrary method execution with controlled parameters",
                "recommendation": "Validate method names and parameters, use static method calls where possible",
                "requires_context": ["input", "bundle", "intent"]
            },
            
            # MODERATE RISK - Potentially dangerous but common patterns
            "dex_class_loader": {
                "pattern": r"(?:DexClassLoader|PathClassLoader)\s*\([^)]*(?:getExternalStorage|sdcard|download|cache)[^)]*\)",
                "risk": RiskLevel.MODERATE,
                "description": "Dynamic class loading from external storage",
                "impact": "Loading untrusted code from external sources",
                "recommendation": "Load classes only from internal app directory, verify code integrity",
                "requires_context": ["external", "storage", "sdcard", "download"]
            },
            
            "webview_js_bridge": {
                "pattern": r"addJavascriptInterface\s*\([^,]*,\s*[^)]*\)|evaluateJavascript\s*\([^)]*(?:getString|input|param)[^)]*\)",
                "risk": RiskLevel.MODERATE,
                "description": "WebView JavaScript bridge with dynamic content",
                "impact": "JavaScript injection, access to native methods",
                "recommendation": "Sanitize JavaScript content, restrict bridge methods, use targetSdkVersion 17+",
                "requires_context": ["javascript", "bridge", "webview"]
            },
            
            "native_library_external": {
                "pattern": r"System\.load(?:Library)?\s*\([^)]*(?:getExternalStorage|sdcard|download|cache)[^)]*\)",
                "risk": RiskLevel.MODERATE,
                "description": "Loading native libraries from external storage",
                "impact": "Loading malicious native code",
                "recommendation": "Load libraries only from app's lib directory, verify library integrity",
                "requires_context": ["external", "storage", "download"]
            },
            
            "sql_injection_risk": {
                "pattern": r"(?:rawQuery|execSQL)\s*\([^)]*(?:\+|getString|input|param)[^)]*\)",
                "risk": RiskLevel.MODERATE,
                "description": "SQL query with string concatenation",
                "impact": "SQL injection vulnerability",
                "recommendation": "Use parameterized queries, prepared statements, or SQLiteDatabase query methods",
                "requires_context": ["query", "sql", "database"]
            },
            
            "intent_redirection": {
                "pattern": r"startActivity\s*\(\s*getIntent\(\)\)|startActivity\s*\([^)]*getParcelableExtra[^)]*\)",
                "risk": RiskLevel.MODERATE,
                "description": "Intent redirection vulnerability",
                "impact": "Unauthorized access to protected components",
                "recommendation": "Validate intent destinations, use explicit intents, check caller permissions",
                "requires_context": ["intent", "redirect", "activity"]
            }
        }
        
        # Safe patterns that should reduce confidence if found nearby
        self.safe_patterns = [
            r"(?:equals|contains|matches)\s*\(\s*[\"'][^\"']*[\"']\s*\)",  # String literal comparisons
            r"(?:startsWith|endsWith)\s*\(\s*[\"'][^\"']*[\"']\s*\)",      # String prefix/suffix checks
            r"Pattern\.matches\s*\(",                                      # Regex validation
            r"if\s*\([^)]*(?:isEmpty|isNull|equals)[^)]*\)",              # Null/empty checks
            r"(?:whitelist|allowlist|permitted|allowed)",                  # Explicit allow lists
            r"(?:validate|sanitize|clean|escape)",                        # Input validation
        ]

    def scan_file(self, file_path: str) -> None:
        """Scan a single file for security vulnerabilities."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()
                
            # Skip if file is too small or doesn't contain relevant code
            if len(content) < 100 or not self._contains_relevant_code(content):
                return
                
            for line_num, line in enumerate(lines, 1):
                self._analyze_line(file_path, line_num, line, lines, content)
                
        except Exception as e:
            if os.getenv('DEBUG'):
                print(f"Error scanning {file_path}: {e}")

    def _contains_relevant_code(self, content: str) -> bool:
        """Check if file contains code patterns worth analyzing."""
        relevant_keywords = [
            'Runtime', 'Process', 'Class.forName', 'Method.invoke',
            'DexClassLoader', 'WebView', 'System.load', 'startActivity'
        ]
        return any(keyword in content for keyword in relevant_keywords)

    def _analyze_line(self, file_path: str, line_num: int, line: str, all_lines: List[str], full_content: str) -> None:
        """Analyze a single line for security patterns."""
        line_stripped = line.strip()
        
        # Skip comments, empty lines, and imports
        if (not line_stripped or 
            line_stripped.startswith(('//','/*', '*', 'import ', 'package '))):
            return
            
        # Check each security pattern
        for pattern_id, pattern_info in self.security_patterns.items():
            match = re.search(pattern_info["pattern"], line, re.IGNORECASE)
            if match:
                # Calculate confidence based on context
                confidence = self._calculate_confidence(
                    pattern_info, line_stripped, all_lines, line_num, full_content
                )
                
                # Only report high-confidence findings
                if confidence >= 0.6:
                    context = self._get_method_context(all_lines, line_num)
                    method_name = self._extract_method_name(all_lines, line_num)
                    
                    # Create unique hash to prevent duplicates
                    finding_hash = hashlib.md5(
                        f"{file_path}:{line_num}:{pattern_id}:{line_stripped}".encode()
                    ).hexdigest()
                    
                    if finding_hash not in self.processed_hashes:
                        finding = SecurityFinding(
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line_stripped,
                            pattern_id=pattern_id,
                            risk_level=pattern_info["risk"],
                            description=pattern_info["description"],
                            impact=pattern_info["impact"],
                            recommendation=pattern_info["recommendation"],
                            confidence=confidence,
                            context=context,
                            method_name=method_name
                        )
                        
                        self.findings.append(finding)
                        self.processed_hashes.add(finding_hash)

    def _calculate_confidence(self, pattern_info: Dict, line: str, all_lines: List[str], 
                            line_num: int, full_content: str) -> float:
        """Calculate confidence score for a finding."""
        confidence = 0.5  # Base confidence
        
        # Check for required context keywords
        context_window = self._get_context_lines(all_lines, line_num, 5)
        context_text = ' '.join(context_window).lower()
        
        required_context = pattern_info.get("requires_context", [])
        context_matches = sum(1 for keyword in required_context if keyword in context_text)
        
        if required_context:
            confidence += (context_matches / len(required_context)) * 0.3
        
        # Reduce confidence if safe patterns are nearby
        safe_pattern_count = sum(1 for pattern in self.safe_patterns 
                               if re.search(pattern, context_text, re.IGNORECASE))
        confidence -= safe_pattern_count * 0.15
        
        # Increase confidence for specific dangerous patterns
        if any(dangerous in line.lower() for dangerous in ['eval', 'exec', 'system', 'shell']):
            confidence += 0.2
            
        # Check if input comes from external sources
        external_sources = ['getintent', 'bundle', 'getstring', 'uri', 'url', 'http']
        if any(source in context_text for source in external_sources):
            confidence += 0.2
            
        # Reduce confidence for test files
        if any(test_indicator in full_content.lower() for test_indicator in 
               ['@test', 'junit', 'testcase', 'mockito']):
            confidence -= 0.3
            
        return max(0.0, min(1.0, confidence))

    def _get_context_lines(self, lines: List[str], line_num: int, window_size: int) -> List[str]:
        """Get surrounding lines for context analysis."""
        start = max(0, line_num - window_size - 1)
        end = min(len(lines), line_num + window_size)
        return [lines[i].strip() for i in range(start, end)]

    def _get_method_context(self, lines: List[str], line_num: int) -> List[str]:
        """Get method context for the finding."""
        method_start = self._find_method_start(lines, line_num)
        context_size = 5
        start = max(method_start, line_num - context_size - 1)
        end = min(len(lines), line_num + context_size)
        
        return [f"{i+1}: {lines[i].strip()}" for i in range(start, end) 
                if lines[i].strip() and not lines[i].strip().startswith(('//','/*', '*'))]

    def _find_method_start(self, lines: List[str], line_num: int) -> int:
        """Find the start of the method containing the given line."""
        for i in range(line_num - 1, max(0, line_num - 50), -1):
            line = lines[i].strip()
            if re.match(r'^\s*(?:public|private|protected|static|final)*\s*\w+.*\([^)]*\)\s*\{?', line):
                return i
        return max(0, line_num - 10)

    def _extract_method_name(self, lines: List[str], line_num: int) -> Optional[str]:
        """Extract method name containing the finding."""
        method_start = self._find_method_start(lines, line_num)
        if method_start < len(lines):
            line = lines[method_start].strip()
            match = re.search(r'\b(\w+)\s*\([^)]*\)', line)
            return match.group(1) if match else None
        return None

    def scan_directory(self, directory: str) -> None:
        """Recursively scan directory for source files."""
        print(f"Scanning directory: {directory}")
        
        # Focus on source files most likely to contain security issues
        target_extensions = {'.java', '.kt', '.smali'}
        security_relevant_dirs = {'activity', 'service', 'receiver', 'provider', 'network', 'crypto', 'auth'}
        
        for root, dirs, files in os.walk(directory):
            # Skip irrelevant directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', '__pycache__', 'node_modules', '.gradle', 'build',
                'test', 'androidTest', 'debug', 'release'
            }]
            
            # Prioritize security-relevant directories
            is_security_relevant = any(sec_dir in root.lower() for sec_dir in security_relevant_dirs)
            
            for file in files:
                if any(file.endswith(ext) for ext in target_extensions):
                    # Skip test files
                    if 'test' in file.lower() or 'Test' in file:
                        continue
                        
                    file_path = os.path.join(root, file)
                    self.scan_file(file_path)
                    self.scanned_files += 1
                    
                    if self.scanned_files % 50 == 0:
                        print(f"Scanned {self.scanned_files} files...")

    def generate_report(self, output_format: str = 'text') -> str:
        """Generate a professional security report."""
        if output_format == 'json':
            return self._generate_json_report()
        else:
            return self._generate_security_report()

    def _generate_security_report(self) -> str:
        """Generate professional security assessment report."""
        # Sort findings by risk level and confidence
        sorted_findings = sorted(self.findings, 
                               key=lambda x: (x.risk_level.value, -x.confidence, x.file_path))
        
        report = []
        report.append("=" * 80)
        report.append("ANDROID SECURITY ASSESSMENT REPORT")
        report.append("=" * 80)
        report.append(f"Files Analyzed: {self.scanned_files}")
        report.append(f"Security Findings: {len(self.findings)}")
        
        # Executive summary
        high_risk = [f for f in self.findings if f.risk_level == RiskLevel.HIGH]
        moderate_risk = [f for f in self.findings if f.risk_level == RiskLevel.MODERATE]
        
        report.append(f"\nEXECUTIVE SUMMARY:")
        report.append(f"  High Risk Issues: {len(high_risk)}")
        report.append(f"  Moderate Risk Issues: {len(moderate_risk)}")
        
        if high_risk:
            report.append(f"\n🔴 CRITICAL: {len(high_risk)} high-risk vulnerabilities require immediate attention")
        if moderate_risk:
            report.append(f"🟡 WARNING: {len(moderate_risk)} moderate-risk issues should be reviewed")

        # Detailed findings by risk level
        for risk_level in [RiskLevel.HIGH, RiskLevel.MODERATE]:
            risk_findings = [f for f in sorted_findings if f.risk_level == risk_level]
            if not risk_findings:
                continue
                
            report.append(f"\n{'=' * 60}")
            report.append(f"{risk_level.value} RISK VULNERABILITIES ({len(risk_findings)})")
            report.append(f"{'=' * 60}")
            
            for i, finding in enumerate(risk_findings, 1):
                report.append(f"\n[{risk_level.value[0]}{i:02d}] {finding.description}")
                report.append(f"File: {finding.file_path}")
                report.append(f"Line: {finding.line_number}")
                if finding.method_name:
                    report.append(f"Method: {finding.method_name}()")
                report.append(f"Confidence: {finding.confidence:.1%}")
                report.append(f"Code: {finding.line_content}")
                report.append(f"\nIMPACT: {finding.impact}")
                report.append(f"RECOMMENDATION: {finding.recommendation}")
                
                if finding.context:
                    report.append("\nCode Context:")
                    for ctx_line in finding.context[-5:]:  # Show relevant context
                        report.append(f"  {ctx_line}")
                
                report.append(f"{'-' * 40}")
        
        # Summary recommendations
        if self.findings:
            report.append(f"\nNEXT STEPS:")
            report.append("1. Address all HIGH risk findings immediately")
            report.append("2. Review and remediate MODERATE risk findings")
            report.append("3. Implement secure coding practices")
            report.append("4. Consider additional security testing (DAST, penetration testing)")
            report.append("5. Regular security code reviews")
        
        return '\n'.join(report)

    def _generate_json_report(self) -> str:
        """Generate machine-readable JSON report."""
        findings_data = []
        for finding in self.findings:
            findings_data.append({
                "id": f"{finding.pattern_id}_{finding.line_number}",
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "method_name": finding.method_name,
                "risk_level": finding.risk_level.value,
                "confidence": round(finding.confidence, 2),
                "description": finding.description,
                "impact": finding.impact,
                "recommendation": finding.recommendation,
                "code": finding.line_content,
                "context": finding.context
            })
        
        report_data = {
            "scan_metadata": {
                "files_scanned": self.scanned_files,
                "total_findings": len(self.findings),
                "high_risk_count": len([f for f in self.findings if f.risk_level == RiskLevel.HIGH]),
                "moderate_risk_count": len([f for f in self.findings if f.risk_level == RiskLevel.MODERATE])
            },
            "findings": findings_data
        }
        
        return json.dumps(report_data, indent=2)

    def save_report(self, filename: str, output_format: str = 'text') -> None:
        """Save report to file."""
        report = self.generate_report(output_format)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Security report saved to: {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Professional Android Security Scanner - Focus on high-confidence vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 android_security_scanner.py /path/to/decompiled/app
  python3 android_security_scanner.py /path/to/app --output-format json --save-report security_report.json
  python3 android_security_scanner.py /path/to/app --verbose
        """
    )
    
    parser.add_argument('target', help='Path to decompiled Android application directory or file')
    parser.add_argument('--output-format', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--save-report', help='Save report to specified file')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--min-confidence', type=float, default=0.6,
                       help='Minimum confidence threshold (0.0-1.0, default: 0.6)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.target):
        print(f"Error: Target path '{args.target}' does not exist")
        return 1
    
    # Set debug environment for verbose mode
    if args.verbose:
        os.environ['DEBUG'] = '1'
    
    scanner = AndroidSecurityScanner()
    
    try:
        if os.path.isfile(args.target):
            scanner.scan_file(args.target)
        else:
            scanner.scan_directory(args.target)
        
        # Filter findings by confidence threshold
        scanner.findings = [f for f in scanner.findings if f.confidence >= args.min_confidence]
        
        print(f"\nScan completed.")
        print(f"Files analyzed: {scanner.scanned_files}")
        print(f"Security findings: {len(scanner.findings)}")
        
        if scanner.findings:
            high_risk = len([f for f in scanner.findings if f.risk_level == RiskLevel.HIGH])
            moderate_risk = len([f for f in scanner.findings if f.risk_level == RiskLevel.MODERATE])
            
            if high_risk > 0:
                print(f"🔴 HIGH RISK: {high_risk} critical security issues found!")
            if moderate_risk > 0:
                print(f"🟡 MODERATE RISK: {moderate_risk} security concerns identified")
        else:
            print("✅ No high-confidence security issues detected")
        
        if args.save_report:
            scanner.save_report(args.save_report, args.output_format)
        else:
            print("\n" + scanner.generate_report(args.output_format))
            
        return 0
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        return 1
    except Exception as e:
        print(f"Error during scan: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
