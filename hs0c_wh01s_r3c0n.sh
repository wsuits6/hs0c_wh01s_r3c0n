#!/usr/bin/env bash
set -euo pipefail

# === Colors & Formatting ===
RED="\033[1;31m"
GREEN="\033[1;32m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
MAGENTA="\033[1;35m"
BLUE="\033[1;34m"
BOLD="\033[1m"
DIM="\033[2m"
RESET="\033[0m"

# === Configuration ===
OUTPUT_DIR="./hsociety_recon"
SAVE_REPORTS=false
VERBOSE=false
TIMEOUT=10

# === Functions ===
print_banner() {
  clear
  cat <<'HSOCIETY'
██████████████████████████████████████████████████████████████████████████
██████████████████████████████████████████████████████████████████████████
███████████████                                            ███████████████
███████████████  ████████████████████████████████████████  ███████████████
███████████████  ███████████                  ███████████  ███████████████
███████████████  ███████     ████████████████     ███████  ███████████████
███████████████  █████   ████████████████████████   █████  ███████████████
███████████████  ███   ████████████████████████████   ███  ███████████████
████████████████ ██  ███         █████████        ███  ██  ███████████████
███████████████  ██      ███████   ████    ██████      ██  ███████████████
███████████████  █ ██ ████████████      ████████████ ██ █  ███████████████
███████████████  ████ █       ██████  ██████       █ ████  ███████████████
███████████████  ████  █        ████   ███       █ █ ████  ███████████████
███████████████  █    █   ██████          ██████   █    █  ███████████████
███████████████  █  █ █  ████████  █  █  ████████  █ █  █  ███████████████
███████████████  █ ██   █      █   █  █   █      █    █ █  ███████████████
███████████████  █    ██  ████   ██    ██   ████  ██    █  ███████████████
███████████████  █  ███  ████   █   ██   █   ████  ███  █  ███████████████
███████████████  █ ████        ████     ███        ████ █  ███████████████
███████████████  █  ███████████████████████████████████ █  ███████████████
███████████████  ██ ██████████████████████████████████ ██  ███████████████
███████████████  ███  ███████████████████████████████ ███  ███████████████
███████████████  ████     ████              █████    ████  ███████████████
███████████████  █████        ██████████████        █████  ███████████████
███████████████  █████  █████     ███████    █████  █████  ███████████████
███████████████  ██████  ███████          ███████  ██████  ███████████████
███████████████  ███████  █████████████████████   ███████  ███████████████
███████████████  ████████    █████████████████   ████████  ███████████████
███████████████  ██████████   ██████████████   ██████████  ███████████████
███████████████  ████████████                ████████████  ███████████████
███████████████  ████████████████████████████████████████  ███████████████
███████████████                                            ███████████████
███████████████  ██ ██ ██████████ █████ ██ ███████████ ██  ███████████████
███████████████  ██ ██ ██   ██  █ ██    ██ █     █   ███   ███████████████
███████████████  ██ ██   ██ ██  █ ██    ██ ████ ██   ███   ███████████████
███████████████  ██ ██ ██ ████  █ ██ ██ ██ █    ██    ██   ███████████████
███████████████  ██ ██  ███   ██   ███  ██ ████  █    █    ███████████████
███████████████                                            ███████████████
██████████████████████████████████████████████████████████████████████████
██████████████████████████████████████████████████████████████████████████
HSOCIETY
  echo -e "\n${CYAN}${BOLD}           -= HSOCIETY Reconnaissance Framework =-${RESET}"
  echo -e "${DIM}              Educational & Ethical Use Only${RESET}\n"
}

show_usage() {
  cat <<EOF
${BOLD}Usage:${RESET} $0 [OPTIONS] <domain>

${BOLD}Options:${RESET}
  -s, --save         Save output to file
  -v, --verbose      Show verbose output
  -t, --timeout N    Set timeout for operations (default: 10s)
  -o, --output DIR   Output directory (default: ./hsociety_recon)
  -h, --help         Show this help message

${BOLD}Examples:${RESET}
  $0 example.com
  $0 -s -v example.com
  $0 --save --timeout 15 example.com

EOF
  exit 0
}

log_info() {
  echo -e "${CYAN}[*]${RESET} $1"
}

log_success() {
  echo -e "${GREEN}[✓]${RESET} $1"
}

log_error() {
  echo -e "${RED}[!]${RESET} $1"
}

log_warn() {
  echo -e "${YELLOW}[!]${RESET} $1"
}

spinner() {
  local pid=$1
  local delay=0.1
  local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  while kill -0 $pid 2>/dev/null; do
    local temp=${spinstr#?}
    printf " [${CYAN}%c${RESET}]  " "$spinstr"
    spinstr=$temp${spinstr%"$temp"}
    sleep $delay
    printf "\b\b\b\b\b\b"
  done
  printf "    \b\b\b\b"
}

section_header() {
  echo -e "\n${YELLOW}${BOLD}╔════════════════════════════════════════╗${RESET}"
  echo -e "${YELLOW}${BOLD}║${RESET} $1"
  echo -e "${YELLOW}${BOLD}╚════════════════════════════════════════╝${RESET}"
}

check_dependencies() {
  local deps=("whois" "dig" "curl" "jq")
  local missing=()
  
  for cmd in "${deps[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
      missing+=("$cmd")
    fi
  done
  
  if [ ${#missing[@]} -gt 0 ]; then
    log_error "Missing dependencies: ${missing[*]}"
    echo -e "${YELLOW}Install with:${RESET}"
    echo "  Ubuntu/Debian: sudo apt install ${missing[*]}"
    echo "  macOS: brew install ${missing[*]}"
    exit 1
  fi
  
  if [ "$VERBOSE" = true ]; then
    log_success "All dependencies found"
  fi
}

validate_domain() {
  local domain=$1
  
  # Basic domain validation
  if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
    log_error "Invalid domain format: $domain"
    exit 1
  fi
  
  # Check if domain resolves
  if ! dig +short A "$domain" +time=$TIMEOUT &>/dev/null; then
    log_warn "Domain may not resolve or is unreachable"
    echo -ne "${YELLOW}Continue anyway? (y/N):${RESET} "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
      exit 1
    fi
  fi
}

init_output() {
  if [ "$SAVE_REPORTS" = true ]; then
    mkdir -p "$OUTPUT_DIR"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    OUTPUT_FILE="$OUTPUT_DIR/${DOMAIN}_${timestamp}.txt"
    log_info "Output will be saved to: $OUTPUT_FILE"
    
    # Redirect output to both terminal and file
    exec > >(tee -a "$OUTPUT_FILE") 2>&1
  fi
}

# === Reconnaissance Modules ===

module_whois() {
  section_header "WHOIS Information"
  
  local temp_file=$(mktemp)
  timeout $TIMEOUT whois "$DOMAIN" > "$temp_file" 2>/dev/null || {
    log_error "WHOIS lookup failed or timed out"
    rm -f "$temp_file"
    return 1
  }
  
  if [ ! -s "$temp_file" ]; then
    log_warn "No WHOIS data available"
    rm -f "$temp_file"
    return 1
  fi
  
  # Parse and display relevant information
  echo -e "${BOLD}Registrar Information:${RESET}"
  grep -i "Registrar:" "$temp_file" | head -3 | sed "s/^/  ${GREEN}→${RESET} /"
  
  echo -e "\n${BOLD}Registration Dates:${RESET}"
  grep -iE "Creation Date|Created:|Registered on" "$temp_file" | head -1 | sed "s/^/  ${GREEN}→${RESET} /"
  grep -iE "Expiry|Expiration|Expires" "$temp_file" | head -1 | sed "s/^/  ${GREEN}→${RESET} /"
  grep -iE "Updated|Modified|Last updated" "$temp_file" | head -1 | sed "s/^/  ${GREEN}→${RESET} /"
  
  echo -e "\n${BOLD}Name Servers:${RESET}"
  grep -i "Name Server:" "$temp_file" | sed "s/^/  ${GREEN}→${RESET} /"
  
  if [ "$VERBOSE" = true ]; then
    echo -e "\n${BOLD}Registrant Contact:${RESET}"
    grep -iE "Registrant|Registry Registrant ID" "$temp_file" | head -5 | sed "s/^/  ${GREEN}→${RESET} /"
  fi
  
  rm -f "$temp_file"
  log_success "WHOIS lookup complete"
}

module_dns() {
  section_header "DNS Records"
  
  local records_found=0
  
  # A Records
  echo -e "${BOLD}A Records (IPv4):${RESET}"
  local a_records=$(timeout $TIMEOUT dig +short A "$DOMAIN" 2>/dev/null)
  if [ -n "$a_records" ]; then
    echo "$a_records" | while read -r ip; do
      echo -e "  ${GREEN}→${RESET} ${CYAN}$ip${RESET}"
      ((records_found++))
    done
  else
    echo -e "  ${DIM}No A records found${RESET}"
  fi
  
  # AAAA Records (IPv6)
  echo -e "\n${BOLD}AAAA Records (IPv6):${RESET}"
  local aaaa_records=$(timeout $TIMEOUT dig +short AAAA "$DOMAIN" 2>/dev/null)
  if [ -n "$aaaa_records" ]; then
    echo "$aaaa_records" | while read -r ip; do
      echo -e "  ${GREEN}→${RESET} ${CYAN}$ip${RESET}"
      ((records_found++))
    done
  else
    echo -e "  ${DIM}No AAAA records found${RESET}"
  fi
  
  # NS Records
  echo -e "\n${BOLD}Name Servers:${RESET}"
  local ns_records=$(timeout $TIMEOUT dig +short NS "$DOMAIN" 2>/dev/null)
  if [ -n "$ns_records" ]; then
    echo "$ns_records" | while read -r ns; do
      echo -e "  ${GREEN}→${RESET} $ns"
      ((records_found++))
    done
  else
    echo -e "  ${DIM}No NS records found${RESET}"
  fi
  
  # MX Records
  echo -e "\n${BOLD}Mail Servers:${RESET}"
  local mx_records=$(timeout $TIMEOUT dig +short MX "$DOMAIN" 2>/dev/null)
  if [ -n "$mx_records" ]; then
    echo "$mx_records" | while read -r priority server; do
      echo -e "  ${GREEN}→${RESET} [Priority: $priority] $server"
      ((records_found++))
    done
  else
    echo -e "  ${DIM}No MX records found${RESET}"
  fi
  
  # TXT Records
  echo -e "\n${BOLD}TXT Records:${RESET}"
  local txt_records=$(timeout $TIMEOUT dig +short TXT "$DOMAIN" 2>/dev/null)
  if [ -n "$txt_records" ]; then
    echo "$txt_records" | while read -r txt; do
      # Truncate long TXT records
      if [ ${#txt} -gt 80 ]; then
        echo -e "  ${GREEN}→${RESET} ${txt:0:80}..."
      else
        echo -e "  ${GREEN}→${RESET} $txt"
      fi
      ((records_found++))
    done
  else
    echo -e "  ${DIM}No TXT records found${RESET}"
  fi
  
  # CNAME Record
  echo -e "\n${BOLD}CNAME Record:${RESET}"
  local cname_record=$(timeout $TIMEOUT dig +short CNAME "$DOMAIN" 2>/dev/null)
  if [ -n "$cname_record" ]; then
    echo -e "  ${GREEN}→${RESET} $cname_record"
    ((records_found++))
  else
    echo -e "  ${DIM}No CNAME record found${RESET}"
  fi
  
  log_success "DNS enumeration complete ($records_found records)"
}

module_subdomains() {
  section_header "Subdomain Discovery (crt.sh)"
  
  log_info "Querying certificate transparency logs..."
  
  local temp_file=$(mktemp)
  timeout $TIMEOUT curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" > "$temp_file" 2>/dev/null || {
    log_error "Failed to fetch certificate data"
    rm -f "$temp_file"
    return 1
  }
  
  if [ ! -s "$temp_file" ]; then
    log_warn "No certificate data found"
    rm -f "$temp_file"
    return 1
  fi
  
  local subdomains=$(jq -r '.[].name_value' "$temp_file" 2>/dev/null | sort -u)
  local count=$(echo "$subdomains" | wc -l)
  
  if [ -z "$subdomains" ] || [ "$count" -eq 0 ]; then
    log_warn "No subdomains found"
    rm -f "$temp_file"
    return 1
  fi
  
  log_success "Found $count unique subdomain(s)"
  
  echo -e "\n${BOLD}Discovered Subdomains:${RESET}"
  echo "$subdomains" | while read -r sub; do
    # Remove wildcards
    sub=$(echo "$sub" | sed 's/^\*\.//g')
    echo -e "  ${GREEN}→${RESET} ${CYAN}$sub${RESET}"
  done
  
  # Save subdomains for next module
  echo "$subdomains" | sed 's/^\*\.//g' > "$temp_file.subs"
  
  rm -f "$temp_file"
}

module_subdomain_ips() {
  section_header "Subdomain Resolution"
  
  local temp_file=$(mktemp)
  temp_file="$temp_file.subs"
  
  if [ ! -f "$temp_file" ]; then
    log_warn "No subdomains to resolve (run subdomain discovery first)"
    return 1
  fi
  
  log_info "Resolving subdomain IP addresses..."
  
  local resolved=0
  local total=$(wc -l < "$temp_file")
  
  while read -r sub; do
    [ -z "$sub" ] && continue
    
    local ip=$(timeout $TIMEOUT dig +short A "$sub" 2>/dev/null | head -1)
    
    if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo -e "  ${GREEN}$sub${RESET} → ${CYAN}$ip${RESET}"
      echo "$ip" >> "$temp_file.ips"
      ((resolved++))
    elif [ "$VERBOSE" = true ]; then
      echo -e "  ${DIM}$sub${RESET} → ${DIM}no resolution${RESET}"
    fi
  done < "$temp_file"
  
  if [ $resolved -eq 0 ]; then
    log_warn "No subdomains resolved to IP addresses"
  else
    log_success "Resolved $resolved/$total subdomains"
  fi
  
  rm -f "$temp_file"
}

module_ip_whois() {
  section_header "IP WHOIS Lookup"
  
  # Get main domain IPs
  local ips=$(timeout $TIMEOUT dig +short A "$DOMAIN" 2>/dev/null)
  
  # Add subdomain IPs if available
  local temp_file=$(mktemp)
  temp_file="$temp_file.subs.ips"
  if [ -f "$temp_file" ]; then
    ips="$ips"$'\n'"$(cat "$temp_file" 2>/dev/null)"
    rm -f "$temp_file"
  fi
  
  # Deduplicate IPs
  ips=$(echo "$ips" | sort -u | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
  
  if [ -z "$ips" ]; then
    log_warn "No IPs to lookup"
    return 1
  fi
  
  local count=$(echo "$ips" | wc -l)
  log_info "Looking up WHOIS for $count unique IP(s)..."
  
  echo "$ips" | while read -r ip; do
    [ -z "$ip" ] && continue
    
    echo -e "\n${BOLD}${CYAN}$ip${RESET}${BOLD}:${RESET}"
    
    local whois_data=$(timeout $TIMEOUT whois "$ip" 2>/dev/null)
    
    if [ -z "$whois_data" ]; then
      echo -e "  ${DIM}No WHOIS data available${RESET}"
      continue
    fi
    
    # Parse relevant fields
    echo "$whois_data" | grep -iE "OrgName|Organization" | head -1 | sed "s/^/  ${GREEN}→${RESET} /"
    echo "$whois_data" | grep -iE "Country" | head -1 | sed "s/^/  ${GREEN}→${RESET} /"
    echo "$whois_data" | grep -iE "NetRange|CIDR|inetnum" | head -1 | sed "s/^/  ${GREEN}→${RESET} /"
    
    if [ "$VERBOSE" = true ]; then
      echo "$whois_data" | grep -iE "NetName|OrgId" | head -2 | sed "s/^/  ${GREEN}→${RESET} /"
    fi
  done
  
  log_success "IP WHOIS lookup complete"
}

module_tech_detection() {
  section_header "Technology Detection"
  
  log_info "Checking HTTP headers and technologies..."
  
  local url="https://$DOMAIN"
  
  # Try HTTPS first, fall back to HTTP
  local response=$(timeout $TIMEOUT curl -sI "$url" 2>/dev/null)
  if [ -z "$response" ]; then
    url="http://$DOMAIN"
    response=$(timeout $TIMEOUT curl -sI "$url" 2>/dev/null)
  fi
  
  if [ -z "$response" ]; then
    log_warn "Could not connect to $DOMAIN"
    return 1
  fi
  
  echo -e "${BOLD}HTTP Headers:${RESET}"
  echo "$response" | grep -iE "Server:|X-Powered-By:|X-AspNet-Version:|X-Framework:" | sed "s/^/  ${GREEN}→${RESET} /"
  
  echo -e "\n${BOLD}Security Headers:${RESET}"
  local security_headers=$(echo "$response" | grep -iE "Strict-Transport-Security:|X-Frame-Options:|X-Content-Type-Options:|Content-Security-Policy:")
  
  if [ -n "$security_headers" ]; then
    echo "$security_headers" | sed "s/^/  ${GREEN}→${RESET} /"
  else
    echo -e "  ${YELLOW}⚠${RESET} No common security headers found"
  fi
  
  # Check for common technologies
  echo -e "\n${BOLD}Technology Indicators:${RESET}"
  local body=$(timeout $TIMEOUT curl -sL "$url" 2>/dev/null | head -100)
  
  echo "$body" | grep -iq "wordpress" && echo -e "  ${GREEN}→${RESET} WordPress detected"
  echo "$body" | grep -iq "joomla" && echo -e "  ${GREEN}→${RESET} Joomla detected"
  echo "$body" | grep -iq "drupal" && echo -e "  ${GREEN}→${RESET} Drupal detected"
  echo "$body" | grep -iq "django" && echo -e "  ${GREEN}→${RESET} Django detected"
  echo "$body" | grep -iq "react" && echo -e "  ${GREEN}→${RESET} React detected"
  echo "$body" | grep -iq "angular" && echo -e "  ${GREEN}→${RESET} Angular detected"
  echo "$body" | grep -iq "vue\.js" && echo -e "  ${GREEN}→${RESET} Vue.js detected"
  
  log_success "Technology detection complete"
}

module_ssl_info() {
  section_header "SSL/TLS Certificate Info"
  
  log_info "Checking SSL certificate..."
  
  local cert_info=$(timeout $TIMEOUT echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)
  
  if [ -z "$cert_info" ]; then
    log_warn "Could not retrieve SSL certificate (may not have HTTPS)"
    return 1
  fi
  
  echo -e "${BOLD}Certificate Details:${RESET}"
  
  # Subject
  local subject=$(echo "$cert_info" | grep "Subject:" | sed 's/.*Subject: //')
  echo -e "  ${GREEN}→${RESET} Subject: $subject"
  
  # Issuer
  local issuer=$(echo "$cert_info" | grep "Issuer:" | sed 's/.*Issuer: //')
  echo -e "  ${GREEN}→${RESET} Issuer: $issuer"
  
  # Validity
  echo "$cert_info" | grep -A 2 "Validity" | tail -2 | sed "s/^/  ${GREEN}→${RESET} /"
  
  # SANs
  echo -e "\n${BOLD}Subject Alternative Names:${RESET}"
  echo "$cert_info" | grep -A 1 "Subject Alternative Name" | tail -1 | sed 's/DNS://g' | tr ',' '\n' | sed "s/^/  ${GREEN}→${RESET}/" | head -10
  
  log_success "SSL certificate info retrieved"
}

# === Main Execution ===

main() {
  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case $1 in
      -s|--save)
        SAVE_REPORTS=true
        shift
        ;;
      -v|--verbose)
        VERBOSE=true
        shift
        ;;
      -t|--timeout)
        TIMEOUT="$2"
        shift 2
        ;;
      -o|--output)
        OUTPUT_DIR="$2"
        shift 2
        ;;
      -h|--help)
        print_banner
        show_usage
        ;;
      -*)
        log_error "Unknown option: $1"
        show_usage
        ;;
      *)
        DOMAIN="$1"
        shift
        ;;
    esac
  done
  
  # Validate domain provided
  if [ -z "${DOMAIN:-}" ]; then
    print_banner
    log_error "No domain specified"
    echo ""
    show_usage
  fi
  
  # Initialize
  print_banner
  check_dependencies
  validate_domain "$DOMAIN"
  init_output
  
  # Display scan info
  echo -e "${CYAN}╔════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}║${RESET} ${BOLD}Target:${RESET} ${GREEN}$DOMAIN${RESET}"
  echo -e "${CYAN}║${RESET} ${BOLD}Date:${RESET} $(date '+%Y-%m-%d %H:%M:%S')"
  [ "$SAVE_REPORTS" = true ] && echo -e "${CYAN}║${RESET} ${BOLD}Output:${RESET} $OUTPUT_FILE"
  echo -e "${CYAN}╚════════════════════════════════════════╝${RESET}"
  
  # Run reconnaissance modules
  local start_time=$(date +%s)
  
  module_whois
  module_dns
  module_subdomains
  module_subdomain_ips
  module_ip_whois
  module_tech_detection
  module_ssl_info
  
  # Summary
  local end_time=$(date +%s)
  local duration=$((end_time - start_time))
  
  echo -e "\n${GREEN}${BOLD}╔════════════════════════════════════════╗${RESET}"
  echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Reconnaissance Complete!${RESET}"
  echo -e "${GREEN}${BOLD}║${RESET}  ${DIM}Duration: ${duration}s${RESET}"
  [ "$SAVE_REPORTS" = true ] && echo -e "${GREEN}${BOLD}║${RESET}  ${DIM}Report: $OUTPUT_FILE${RESET}"
  echo -e "${GREEN}${BOLD}╚════════════════════════════════════════╝${RESET}\n"
  
  # Cleanup temp files
  rm -f /tmp/tmp.*.subs /tmp/tmp.*.subs.ips 2>/dev/null
}

# Trap errors
trap 'log_error "Script interrupted"; exit 130' INT TERM

# Run main function
main "$@"