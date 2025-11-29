#!/bin/bash

# RECONMASTER - Nation-State Grade Reconnaissance Automation
# Author: Security Researcher | Quantum Konet Services (Ali Chisom)
# Version: 1.0 | Codename: "SHADOW SCRUTINY"



# Run with this command THREADS=20 RATE_LIMIT=50 ./reconmaster.sh example.com

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "   ____  _____  ______ __  __    _    _____ ____  "
echo "  |  _ \|  __ \|  ____|  \/  |  / \  |_   _/ ___| "
echo "  | |_) | |__) | |__  | \  / | / _ \   | | \___ \ "
echo "  |  _ <|  _  /|  __| | |\/| |/ ___ \  | |  ___) |"
echo "  | |_) | | \ \| |____| |  | /_/   \_\ |_| |____/ "
echo "  |____/|_|  \_|______|_|  |_|recon-master|"
echo -e "${NC}"
echo -e "${YELLOW}[+] Advanced Reconnaissance Automation Framework"
echo -e "[+] Mode: Stealth | OPSEC: Enabled${NC}"
echo ""

# Configuration
TARGET="$1"
OUTPUT_DIR="recon_$(echo $TARGET | sed 's/https:\/\///g; s/\//_/g; s/:/-/g')_$(date +%Y%m%d_%H%M%S)"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
THREADS=50
RATE_LIMIT=100

# OPSEC: Random delay between requests
random_delay() {
    local min_delay=2
    local max_delay=10
    local delay=$((RANDOM % (max_delay - min_delay + 1) + min_delay))
    echo -e "${YELLOW}[OPSEC] Random delay: ${delay}s${NC}"
    sleep $delay
}

# Initialize directories
init_dirs() {
    echo -e "${GREEN}[+] Initializing reconnaissance directories...${NC}"
    mkdir -p $OUTPUT_DIR
    mkdir -p $OUTPUT_DIR/subdomains
    mkdir -p $OUTPUT_DIR/ports
    mkdir -p $OUTPUT_DIR/webservers
    mkdir -p $OUTPUT_DIR/urls
    mkdir -p $OUTPUT_DIR/vulnerabilities
    mkdir -p $OUTPUT_DIR/js
    mkdir -p $OUTPUT_DIR/git
    mkdir -p $OUTPUT_DIR/cloud
    mkdir -p $OUTPUT_DIR/advanced
    mkdir -p $OUTPUT_DIR/raw
}

# Dependency check
check_dependencies() {
    echo -e "${BLUE}[+] Checking dependencies...${NC}"
    local tools=("subfinder" "assetfinder" "amass" "httpx-toolkit" "nuclei" "naabu" "waybackurls" "gau" "katana" "gospider" "ffuf" "dnsx" "notify" "anew" "unfurl" "qsreplace" "dalfox")
    
    for tool in "${tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${RED}[-] $tool not found. Please install it.${NC}"
            exit 1
        fi
    done
    echo -e "${GREEN}[+] All dependencies satisfied${NC}"
}

# Phase 1: Subdomain Enumeration (Multi-Layer)
subdomain_enum() {
    echo -e "${CYAN}[PHASE 1] Subdomain Enumeration${NC}"
    
    # Layer 1: Passive Enumeration
    echo -e "${YELLOW}[+] Passive subdomain discovery...${NC}"
    subfinder -d $TARGET -silent -all | anew $OUTPUT_DIR/subdomains/passive.txt
    assetfinder --subs-only $TARGET | anew $OUTPUT_DIR/subdomains/passive.txt
    random_delay
    
    # Layer 2: Certificate Transparency
    echo -e "${YELLOW}[+] Certificate transparency logs...${NC}"
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' >> $OUTPUT_DIR/raw/cert.txt
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | anew $OUTPUT_DIR/subdomains/cert_transparency.txt
    random_delay
    
    # Layer 3: DNS Brute Forcing
    echo -e "${YELLOW}[+] DNS brute forcing...${NC}"
    puredns bruteforce ./subdomains.txt $TARGET --resolvers ./resolvers.txt | anew $OUTPUT_DIR/subdomains/dns_brute.txt
    random_delay
    
    # Layer 4: Amass Intensive
    echo -e "${YELLOW}[+] Amass intensive enumeration...${NC}"
    amass enum -passive -d $TARGET | anew $OUTPUT_DIR/subdomains/amass_passive.txt
    amass enum -active -d $TARGET | anew $OUTPUT_DIR/subdomains/amass_active.txt
    random_delay
    
    # Combine and deduplicate
    cat $OUTPUT_DIR/subdomains/*.txt | sort -u > $OUTPUT_DIR/subdomains/all_subs.txt
    echo -e "${GREEN}[+] Found $(wc -l $OUTPUT_DIR/subdomains/all_subs.txt | awk '{print $1}') unique subdomains${NC}"
}

# Phase 2: Live Host Verification
live_hosts() {
    echo -e "${CYAN}[PHASE 2] Live Host Discovery${NC}"
    
    # httpx-toolkit with multiple probes
    echo -e "${YELLOW}[+] Verifying live hosts...${NC}"
    httpx-toolkit -silent -l $OUTPUT_DIR/subdomains/all_subs.txt -title -tech-detect -status-code -ip > $OUTPUT_DIR/raw/http_alive.txt
    cat $OUTPUT_DIR/subdomains/all_subs.txt | httpx-toolkit -silent -status-code -title -tech-detect -follow-redirects -random-agent -threads $THREADS -rate-limit $RATE_LIMIT -o $OUTPUT_DIR/webservers/live_hosts.txt
    
    # Extract just the URLs for further processing
    cat $OUTPUT_DIR/webservers/live_hosts.txt | awk '{print $1}' > $OUTPUT_DIR/webservers/live_urls.txt
    echo -e "${GREEN}[+] Found $(wc -l $OUTPUT_DIR/webservers/live_urls.txt | awk '{print $1}') live hosts${NC}"
}

# Phase 3: Port Scanning (Stealth)
port_scanning() {
    echo -e "${CYAN}[PHASE 3] Port Scanning & Service Detection${NC}"
    
    # Fast TCP scan
    echo -e "${YELLOW}[+] TCP port scanning...${NC}"
    naabu -list $OUTPUT_DIR/subdomains/all_subs.txt -top-ports 1000 -exclude-cdn -verify -rate $RATE_LIMIT -silent -o $OUTPUT_DIR/ports/tcp_ports.txt
    
    # Service detection on found ports
    echo -e "${YELLOW}[+] Service detection...${NC}"
    cat $OUTPUT_DIR/ports/tcp_ports.txt | naabu -sV -nmap-cli 'nmap -sV --script=banner -T4' -o $OUTPUT_DIR/ports/services_detected.txt
    
    # UDP scan for critical services
    echo -e "${YELLOW}[+] Critical UDP services...${NC}"
    naabu -list $OUTPUT_DIR/subdomains/all_subs.txt -p 53,123,161,500,514 -udp -verify -silent -o $OUTPUT_DIR/ports/udp_ports.txt
}

# Phase 4: Advanced Web Discovery
web_discovery() {
    echo -e "${CYAN}[PHASE 4] Advanced Web Resource Discovery${NC}"
    
    # Wayback Machine & Archive
    echo -e "${YELLOW}[+] Historical URL discovery...${NC}"
    cat $OUTPUT_DIR/subdomains/all_subs.txt | waybackurls | anew $OUTPUT_DIR/urls/historical.txt
    cat $OUTPUT_DIR/subdomains/all_subs.txt | gau | anew $OUTPUT_DIR/urls/historical.txt
    random_delay
    
    # Spidering
    echo -e "${YELLOW}[+] Spidering live hosts...${NC}"
    katana -list $OUTPUT_DIR/webservers/live_urls.txt -depth 3 -jc -kf -silent -o $OUTPUT_DIR/urls/spidered.txt
    gospider -S $OUTPUT_DIR/webservers/live_urls.txt -d 2 -t $THREADS -c 5 --other-source --subs --sitemap -o $OUTPUT_DIR/urls/gospider_out
    random_delay
    
    # Parameter Discovery
    echo -e "${YELLOW}[+] Parameter discovery...${NC}"
    cat $OUTPUT_DIR/urls/historical.txt $OUTPUT_DIR/urls/spidered.txt | grep "?" | qsreplace -a | tee $OUTPUT_DIR/urls/parameters.txt
    
    # JavaScript Analysis
    echo -e "${YELLOW}[+] JavaScript endpoint extraction...${NC}"
    cat $OUTPUT_DIR/webservers/live_urls.txt | grep "\.js" | anew $OUTPUT_DIR/js/js_urls.txt
    cat $OUTPUT_DIR/js/js_urls.txt | while read url; do
        python3 /home/kali/Desktop/QKS/py/LinkFinder/linkfinder.py -i $url -o cli | anew $OUTPUT_DIR/js/js_endpoints.txt
    done
}

# Phase 5: Directory & File Brute Forcing
directory_brute() {
    echo -e "${CYAN}[PHASE 5] Directory & File Discovery${NC}"
   
    # Loop over all subdomains
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue  # Skip empty lines
        
        echo -e "${YELLOW}[+] Directory brute forcing on ${sub}...${NC}"
        # Sanitize subdomain for filename (replace / and . with _)
        safe_sub=$(echo "$sub" | tr './' '__')
        ffuf -u "https://${sub}/FUZZ" -w ./dirbuster.txt -t $THREADS -rate $RATE_LIMIT -o "$OUTPUT_DIR/urls/ffuf_dirs_${safe_sub}.json"
        
        echo -e "${YELLOW}[+] API endpoint discovery on ${sub}...${NC}"
        ffuf -u "https://${sub}/FUZZ" -w ./api_endpoints.txt -t $THREADS -rate $RATE_LIMIT -o "$OUTPUT_DIR/urls/ffuf_api_${safe_sub}.json"
        
        echo -e "${YELLOW}[+] Backup file discovery on ${sub}...${NC}"
        ffuf -u "https://${sub}/FUZZ" -w ./backup_files.txt -t $THREADS -rate $RATE_LIMIT -o "$OUTPUT_DIR/urls/ffuf_backup_${safe_sub}.json"
    done < "$OUTPUT_DIR/subdomains/all_subs.txt"
}

# Phase 6: Cloud Infrastructure Recon
cloud_recon() {
    echo -e "${CYAN}[PHASE 6] Cloud Infrastructure Discovery${NC}"
    
    # AWS S3 Buckets
    echo -e "${YELLOW}[+] AWS S3 bucket discovery...${NC}"
    cat $OUTPUT_DIR/subdomains/all_subs.txt | aws-s3-enumerator | anew $OUTPUT_DIR/cloud/s3_buckets.txt
    
    # CloudFlare Bypass
    echo -e "${YELLOW}[+] CloudFlare bypass checks...${NC}"
    cat $OUTPUT_DIR/webservers/live_urls.txt | while read url; do
        cloudflared-bypasser $url | anew $OUTPUT_DIR/cloud/cf_bypass.txt
    done
    
    # Azure Discovery
    echo -e "${YELLOW}[+] Azure resource discovery...${NC}"
    cat $OUTPUT_DIR/subdomains/all_subs.txt | grep "azure\|blob.core.windows.net" | anew $OUTPUT_DIR/cloud/azure_resources.txt
}

# Phase 7: Vulnerability Scanning
vulnerability_scan() {
    echo -e "${CYAN}[PHASE 7] Automated Vulnerability Scanning${NC}"
    
    # Nuclei Template Scanning
    echo -e "${YELLOW}[+] Nuclei vulnerability scan...${NC}"
    nuclei -l $OUTPUT_DIR/webservers/live_urls.txt -severity low,medium,high,critical -rate-limit $RATE_LIMIT -o $OUTPUT_DIR/vulnerabilities/nuclei_scan.txt
    
    # Specific vulnerability templates
    echo -e "${YELLOW}[+] CVE-specific scanning...${NC}"    
    nuclei -l $OUTPUT_DIR/webservers/live_urls.txt -severity critical,high -c 50 -rl 100 -json-export $OUTPUT_DIR/vulnerabilities/cves.json -silent

  
    # Exposure scanning
    echo -e "${YELLOW}[+] Exposure scanning...${NC}"
    nuclei -l $OUTPUT_DIR/webservers/live_urls.txt -o $OUTPUT_DIR/vulnerabilities/exposures.txt
    
    # XSS Parameter Testing
    echo -e "${YELLOW}[+] XSS parameter testing...${NC}"
    cat $OUTPUT_DIR/urls/parameters.txt | dalfox pipe --silence --skip-bav -o $OUTPUT_DIR/vulnerabilities/xss.txt
}

# Phase 8: Advanced Reconnaissance
advanced_recon() {
    echo -e "${CYAN}[PHASE 8] Advanced Reconnaissance${NC}"
    
    # GitHub Recon
    echo -e "${YELLOW}[+] GitHub reconnaissance...${NC}"
    python3 /opt/tools/gitdorker/GitDorker.py -t <GITHUB_TOKEN> -q $TARGET -d /opt/tools/gitdorker/Dorks/alldorksv3 -o $OUTPUT_DIR/git/gitdorker_results.txt
    
    # GraphQL Endpoint Discovery
    echo -e "${YELLOW}[+] GraphQL endpoint discovery...${NC}"
    cat $OUTPUT_DIR/webservers/live_urls.txt | while read url; do
        curl -s "$url/graphql" -H "Content-Type: application/json" --data '{"query":"{__schema{types{name}}}"}' | grep -q "data" && echo $url/graphql >> $OUTPUT_DIR/advanced/graphql_endpoints.txt
    done
    
    # JWT Analysis
    echo -e "${YELLOW}[+] JWT token analysis...${NC}"
    cat $OUTPUT_DIR/urls/historical.txt | grep -i "jwt\|token" | anew $OUTPUT_DIR/advanced/jwt_urls.txt
    
    # SSRF Testing Endpoints
    echo -e "${YELLOW}[+] SSRF testing endpoints...${NC}"
    cat $OUTPUT_DIR/urls/historical.txt | grep -i "url\|redirect\|proxy\|request" | anew $OUTPUT_DIR/advanced/ssrf_endpoints.txt
}

# Phase 9: Intelligence Correlation
intelligence_correlation() {
    echo -e "${CYAN}[PHASE 9] Intelligence Correlation & Reporting${NC}"
    
    # Create master findings file
    echo -e "${YELLOW}[+] Correlating findings...${NC}"
    {
        echo "# RECONMASTER INTELLIGENCE REPORT"
        echo "## Target: $TARGET"
        echo "## Date: $(date)"
        echo ""
        echo "## EXECUTIVE SUMMARY"
        echo "- Subdomains Discovered: $(wc -l $OUTPUT_DIR/subdomains/all_subs.txt 2>/dev/null | awk '{print $1}')"
        echo "- Live Hosts: $(wc -l $OUTPUT_DIR/webservers/live_urls.txt 2>/dev/null | awk '{print $1}')"
        echo "- Open Ports: $(wc -l $OUTPUT_DIR/ports/tcp_ports.txt 2>/dev/null | awk '{print $1}')"
        echo "- Vulnerabilities Found: $(wc -l $OUTPUT_DIR/vulnerabilities/nuclei_scan.txt 2>/dev/null | awk '{print $1}')"
        echo ""
        echo "## CRITICAL FINDINGS"
        [ -f "$OUTPUT_DIR/vulnerabilities/cves.json" ] && grep -E "(HIGH|CRITICAL)" $OUTPUT_DIR/vulnerabilities/cves.txt | head -10
        echo ""
        echo "## RECOMMENDATIONS"
        echo "1. Immediate patching of critical vulnerabilities"
        echo "2. Review exposed services and ports"
        echo "3. Implement WAF rules for discovered attack vectors"
        echo "4. Conduct manual penetration testing validation"
    } > $OUTPUT_DIR/FINAL_INTELLIGENCE_REPORT.md
    
    # Generate JSON report for automation
    echo '{"target":"'$TARGET'","subdomains":'$(wc -l $OUTPUT_DIR/subdomains/all_subs.txt 2>/dev/null | awk '{print $1}')',"live_hosts":'$(wc -l $OUTPUT_DIR/webservers/live_urls.txt 2>/dev/null | awk '{print $1}')',"timestamp":"'$(date -Iseconds)'"}' > $OUTPUT_DIR/report.json
}

# Phase 10: Cleanup & OPSEC
opsec_cleanup() {
    echo -e "${CYAN}[PHASE 10] OPSEC Cleanup${NC}"
    
    # Remove temporary files
    echo -e "${YELLOW}[+] Cleaning temporary files...${NC}"
    find $OUTPUT_DIR -name "*.tmp" -delete
    find $OUTPUT_DIR -name "*.json" -size +100M -delete
    
    # Clear tool caches
    echo -e "${YELLOW}[+] Clearing tool caches...${NC}"
    amass db -delete -d $TARGET 2>/dev/null || true
    
    # Final OPSEC delay
    random_delay
    
    echo -e "${GREEN}[+] OPSEC cleanup completed${NC}"
}

# Main execution function
main() {
    if [ -z "$TARGET" ]; then
        echo -e "${RED}[-] Usage: $0 <target>${NC}"
        echo -e "${YELLOW}Example: $0 example.com${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Starting RECONMASTER against: $TARGET${NC}"
    echo -e "${YELLOW}[+] Output directory: $OUTPUT_DIR${NC}"
    
    # Execute phases
    check_dependencies
    init_dirs
    subdomain_enum
    live_hosts
    port_scanning
    web_discovery
    directory_brute
    cloud_recon
    vulnerability_scan
    advanced_recon
    intelligence_correlation
    opsec_cleanup
    
    # Final report
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════╗"
    echo "║         RECONMASTER COMPLETE         ║"
    echo "╠══════════════════════════════════════╣"
    echo "║ Target: $TARGET"
    echo "║ Report: $OUTPUT_DIR/FINAL_INTELLIGENCE_REPORT.md"
    echo "║ Subdomains: $(wc -l $OUTPUT_DIR/subdomains/all_subs.txt 2>/dev/null | awk '{print $1}')"
    echo "║ Live Hosts: $(wc -l $OUTPUT_DIR/webservers/live_urls.txt 2>/dev/null | awk '{print $1}')"
    echo "║ Vulnerabilities: $(wc -l $OUTPUT_DIR/vulnerabilities/nuclei_scan.txt 2>/dev/null | awk '{print $1}')"
    echo "║ Time: $(date)"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
}

# Signal handling for clean exit
trap 'echo -e "${RED}[!] Script interrupted. Performing cleanup...${NC}"; opsec_cleanup; exit 1' INT TERM

# Start main execution
main "$@"
