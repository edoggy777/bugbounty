# Android Security Scanner Suite

# Static analysis tools for identifying security vulnerabilities in Android applications.

# Tools

# file_deeplink.sh
  -Scans for file traversal vulnerabilities in Android deeplinks. Analyzes source code for dangerous patterns.

# sqli_scanner.py
  -Advanced SQL injection scanner for decompiled apps. Features confidence scoring and smart filtering to reduce false positives.

# api.sh
  -scans for api keys in decompiled code

# Usage

# Basic deeplink scan:

  ./file_deeplink.sh /path/to/app/sources
  
# Basic SQL injection scan:

  python3 sqli_scanner.py /path/to/decompiled/app

# High confidence SQL findings only:

  python3 sqli_scanner.py ./app --min-confidence 0.7

# API Scanner

  api.sh /path/to/decompiled_files

# Code Execution

  python3 execute.py /path/to/decompiled_files

# Legal Disclaimer

  These tools are for authorized security testing only. Users must obtain proper authorization and comply with all applicable laws. The authors are not responsible for misuse.
# License

MIT 
