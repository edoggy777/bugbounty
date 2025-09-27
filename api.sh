#!/bin/bash

# Android API Key Scanner - Conservative patterns only
# Based on proven grep patterns with minimal false positives

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  Android API Key Scanner${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
}

print_found() {
    local service=$1
    local pattern=$2
    local file=$3
    local line_num=$4
    local match=$5
    
    echo -e "${RED}[FOUND]${NC} ${YELLOW}$service${NC}"
    echo -e "  Pattern: ${PURPLE}$pattern${NC}"
    echo -e "  File: ${GREEN}$file${NC}:${line_num}"
    echo -e "  Match: ${RED}$match${NC}"
    echo
}

print_summary() {
    local count=$1
    echo -e "${BLUE}================================${NC}"
    if [ $count -eq 0 ]; then
        echo -e "${GREEN}✓ No API keys found${NC}"
    else
        echo -e "${RED}⚠ Found $count potential API key(s)${NC}"
        echo -e "${YELLOW}Please review and secure these keys!${NC}"
    fi
    echo -e "${BLUE}================================${NC}"
}

# Main function
scan_api_keys() {
    local search_path=${1:-.}
    local found_count=0
    
    print_header
    
    echo -e "${BLUE}Scanning path:${NC} $search_path"
    echo -e "${BLUE}Target files:${NC} .java, .xml, .json, .js, .properties, .txt"
    echo
    
    # Define ONLY high-confidence API key patterns with specific prefixes
    declare -A patterns=(
        # Your original proven patterns
        ["Google APIs"]="AIza[0-9A-Za-z_-]{35}"
        ["AWS Access Key"]="AKIA[0-9A-Z]{16}"
        ["Stripe Test Key"]="sk_test_[0-9a-zA-Z]{24,}"
        ["Stripe Live Key"]="sk_live_[0-9a-zA-Z]{24,}"
        ["Twilio Account SID"]="AC[a-z0-9]{30,34}"
        ["SendGrid API Key"]="SG\.[0-9A-Za-z_-]{22,}"
        ["Slack User Token"]="xoxp-[0-9]+-[0-9]+-[0-9]+-[0-9a-f]+"
        ["Slack Bot Token"]="xoxb-[0-9]+-[0-9]+-[0-9a-zA-Z]+"
        ["GitHub Personal Token"]="ghp_[0-9A-Za-z]{36}"
        ["GitHub OAuth Token"]="gho_[0-9A-Za-z]{36}"
        ["Firebase Service Account"]="AAAA[0-9A-Za-z_-]+.*client_email"
        ["Mapbox Public Token"]="pk\.[0-9A-Za-z_-]{60,}"
        ["Mapbox Secret Token"]="sk\.[0-9A-Za-z_-]{60,}"
        
        # High-confidence Android patterns with specific prefixes
        ["AdMob Publisher ID"]="ca-app-pub-[0-9]{16}~[0-9]{10}"
        ["AdMob Ad Unit ID"]="ca-app-pub-[0-9]{16}/[0-9]{10}"
        ["OneSignal App ID"]="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        
        # Your blockchain patterns with specific prefixes
        ["Binance API Key"]="bapi_[0-9A-Za-z]{64,}"
        ["Coinbase API Key"]="api_[0-9A-Za-z]{32,}"
        ["Blockfrost Project ID"]="proj_[0-9A-Za-z]{32,}"
    )
    
    # Check each pattern using recursive grep
    for service in "${!patterns[@]}"; do
        pattern="${patterns[$service]}"
        
        # Use grep -r to find matches with line numbers
        while IFS=: read -r file line_num match; do
            if [[ -n "$match" ]]; then
                print_found "$service" "$pattern" "$file" "$line_num" "$match"
                ((found_count++))
            fi
        done < <(grep -r -n -E "$pattern" "$search_path" --include="*.java" --include="*.xml" --include="*.json" --include="*.js" --include="*.properties" --include="*.txt" 2>/dev/null || true)
    done
    
    print_summary $found_count
    return $found_count
}

# Help function
show_help() {
    echo "Android API Key Scanner"
    echo
    echo "Usage: $0 [OPTIONS] [PATH]"
    echo
    echo "Options:"
    echo "  -h, --help      Show this help message"
    echo "  -v, --verbose   Verbose output"
    echo
    echo "Arguments:"
    echo "  PATH           Directory to scan (default: current directory)"
    echo
    echo "Examples:"
    echo "  $0                          # Scan current directory"
    echo "  $0 /path/to/android/project # Scan specific project"
}

# Parse command line arguments
VERBOSE=false
SEARCH_PATH="."

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -*)
            echo "Unknown option $1"
            show_help
            exit 1
            ;;
        *)
            SEARCH_PATH="$1"
            shift
            ;;
    esac
done

# Validate search path
if [[ ! -d "$SEARCH_PATH" ]]; then
    echo -e "${RED}Error: Directory '$SEARCH_PATH' does not exist${NC}"
    exit 1
fi

# Run the scan
scan_api_keys "$SEARCH_PATH"
scan_result=$?

# Exit with appropriate code
exit $scan_result
