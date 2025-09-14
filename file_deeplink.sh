#!/bin/bash

# Deeplink File Traversal Vulnerability Scanner
# Based on Proximity of variables
# Usage: ./scan_deeplinks.sh [app_directory]

APP_DIR="${1:-.}"
SOURCES_DIR="$APP_DIR/sources"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Output files
REPORT_FILE="deeplink_scan_$(date +%Y%m%d_%H%M%S).txt"
VULNERABLE_FILES=()

echo -e "${BLUE}=== Deeplink File Traversal Vulnerability Scanner ===${NC}"
echo "Scanning directory: $APP_DIR"
echo "Report will be saved to: $REPORT_FILE"
echo ""

# Initialize report
{
    echo "Deeplink File Traversal Vulnerability Scan Report"
    echo "Generated: $(date)"
    echo "Target Directory: $APP_DIR"
    echo "========================================"
    echo ""
} > "$REPORT_FILE"

# Function to log both to console and file
log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
}

# Step 1: Find deeplink handler files
log "${YELLOW}[1] Finding deeplink handler files...${NC}"

if [[ ! -d "$SOURCES_DIR" ]]; then
    log "${RED}Error: Sources directory not found at $SOURCES_DIR${NC}"
    exit 1
fi

# Find files that handle deeplinks
DEEPLINK_FILES=$(find "$SOURCES_DIR" -name "*.java" -exec grep -l -i "deeplink\|intent.*view\|scheme\|getQueryParameter\|getIntent().getData()" {} \;)

if [[ -z "$DEEPLINK_FILES" ]]; then
    log "${RED}No deeplink handler files found.${NC}"
    exit 1
fi

DEEPLINK_COUNT=$(echo "$DEEPLINK_FILES" | wc -l)
log "Found $DEEPLINK_COUNT potential deeplink handler files"
echo "$DEEPLINK_FILES" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Step 2: Check for file operations in deeplink handlers
log "${YELLOW}[2] Checking deeplink handlers for file operations...${NC}"

FILES_WITH_BOTH=()
while IFS= read -r file; do
    # Skip empty lines
    [[ -z "$file" ]] && continue
    
    # Check if file contains both deeplink handling and file operations
    if grep -q -i "getQueryParameter\|getIntent().getData()" "$file" && 
       grep -q -i "FileInputStream\|FileReader\|new File(\|openFile" "$file"; then
        FILES_WITH_BOTH+=("$file")
        log "${YELLOW}POTENTIAL: $file${NC}"
    fi
done <<< "$DEEPLINK_FILES"

if [[ ${#FILES_WITH_BOTH[@]} -eq 0 ]]; then
    log "${GREEN}No files found with both deeplink handling and file operations.${NC}"
    log "This suggests the vulnerability likely doesn't exist."
    exit 0
fi

log "Found ${#FILES_WITH_BOTH[@]} files with both deeplink and file operations"
echo "" >> "$REPORT_FILE"

# Step 3: Deep analysis of suspicious files
log "${YELLOW}[3] Performing deep analysis of suspicious files...${NC}"

for file in "${FILES_WITH_BOTH[@]}"; do
    log "${BLUE}--- Analyzing: $file ---${NC}"
    
    # Look for direct vulnerable patterns
    VULN_PATTERNS=(
        "getQueryParameter.*file.*FileInputStream"
        "getQueryParameter.*path.*FileInputStream"
        "getQueryParameter.*document.*FileInputStream"
        "getQueryParameter.*file.*FileReader"
        "getQueryParameter.*file.*new File"
        "getString.*file.*FileInputStream"
    )
    
    FOUND_VULN=false
    
    for pattern in "${VULN_PATTERNS[@]}"; do
        if grep -i -A 5 -B 5 "$pattern" "$file" > /dev/null 2>&1; then
            log "${RED}VULNERABLE PATTERN FOUND: $pattern${NC}"
            VULNERABLE_FILES+=("$file")
            FOUND_VULN=true
            
            # Extract the vulnerable code
            log "Context:"
            grep -i -A 10 -B 5 "$pattern" "$file" | tee -a "$REPORT_FILE"
            break
        fi
    done
    
    if [[ "$FOUND_VULN" == false ]]; then
        # Look for parameter extraction
        PARAMS=$(grep -i -n "getQueryParameter\|getString" "$file" | head -5)
        FILE_OPS=$(grep -i -n "FileInputStream\|FileReader\|new File(" "$file" | head -5)
        
        if [[ -n "$PARAMS" && -n "$FILE_OPS" ]]; then
            log "${YELLOW}SUSPICIOUS: Contains both patterns but no direct connection found${NC}"
            log "Parameter extraction lines:"
            echo "$PARAMS" | tee -a "$REPORT_FILE"
            log "File operation lines:"
            echo "$FILE_OPS" | tee -a "$REPORT_FILE"
            
            # Check for proximity (within 20 lines)
            PARAM_LINES=$(echo "$PARAMS" | cut -d: -f1)
            FILE_LINES=$(echo "$FILE_OPS" | cut -d: -f1)
            
            for param_line in $PARAM_LINES; do
                for file_line in $FILE_LINES; do
                    DIFF=$((file_line - param_line))
                    if [[ $DIFF -gt 0 && $DIFF -lt 20 ]]; then
                        log "${RED}PROXIMITY ALERT: Parameter at line $param_line, file op at line $file_line (diff: $DIFF)${NC}"
                        VULNERABLE_FILES+=("$file")
                        FOUND_VULN=true
                        break 2
                    fi
                done
            done
        fi
    fi
    
    echo "" >> "$REPORT_FILE"
done

# Step 4: Generate final report
log "${YELLOW}[4] Generating final report...${NC}"

{
    echo ""
    echo "======== SCAN SUMMARY ========"
    echo "Total deeplink handler files: $DEEPLINK_COUNT"
    echo "Files with both deeplinks and file ops: ${#FILES_WITH_BOTH[@]}"
    echo "Potentially vulnerable files: ${#VULNERABLE_FILES[@]}"
    echo ""
} >> "$REPORT_FILE"

if [[ ${#VULNERABLE_FILES[@]} -gt 0 ]]; then
    log "${RED}POTENTIAL VULNERABILITIES FOUND:${NC}"
    for vuln_file in "${VULNERABLE_FILES[@]}"; do
        log "${RED}  - $vuln_file${NC}"
    done
    
    echo "VULNERABLE FILES:" >> "$REPORT_FILE"
    printf '%s\n' "${VULNERABLE_FILES[@]}" >> "$REPORT_FILE"
    
    log ""
    log "${YELLOW}NEXT STEPS:${NC}"
    log "1. Manually review the flagged files"
    log "2. Create a test deeplink: app://open?file=file:///proc/version"
    log "3. Monitor app logs for file content or access attempts"
    log "4. Check if app displays file contents or throws file-related errors"
    
else
    log "${GREEN}No vulnerable patterns found.${NC}"
    log "The app appears to handle deeplinks safely."
fi

log ""
log "Full report saved to: $REPORT_FILE"

# Step 5: Generate test deeplinks if vulnerabilities found
if [[ ${#VULNERABLE_FILES[@]} -gt 0 ]]; then
    DEEPLINK_TEST_FILE="test_deeplinks_$(date +%Y%m%d_%H%M%S).txt"
    
    # Extract app package name
    APP_PACKAGE=$(find "$APP_DIR" -name "AndroidManifest.xml" -exec grep -o 'package="[^"]*"' {} \; | cut -d'"' -f2 | head -1)
    
    if [[ -n "$APP_PACKAGE" ]]; then
        log "${BLUE}Generating test deeplinks for package: $APP_PACKAGE${NC}"
        
        {
            echo "Test Deeplinks for $APP_PACKAGE"
            echo "================================"
            echo ""
            echo "# Basic file access tests"
            echo "adb shell am start -W -a android.intent.action.VIEW -d \"${APP_PACKAGE}://open?file=file:///proc/version\""
            echo "adb shell am start -W -a android.intent.action.VIEW -d \"${APP_PACKAGE}://open?file=file:///system/etc/hosts\""
            echo "adb shell am start -W -a android.intent.action.VIEW -d \"${APP_PACKAGE}://open?path=/proc/version\""
            echo ""
            echo "# Path traversal tests"
            echo "adb shell am start -W -a android.intent.action.VIEW -d \"${APP_PACKAGE}://open?file=file:///../../../proc/version\""
            echo "adb shell am start -W -a android.intent.action.VIEW -d \"${APP_PACKAGE}://open?file=file://%2e%2e%2f%2e%2e%2f%2e%2e%2fproc/version\""
            echo ""
            echo "# Monitor with: adb logcat | grep -i \"linux version\\|kernel\\|proc/version\\|permission\\|denied\""
        } > "$DEEPLINK_TEST_FILE"
        
        log "Test deeplinks saved to: $DEEPLINK_TEST_FILE"
    fi
fi
