#!/bin/bash

# Run autoWin on a range for active redteam engagements
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'


usage() {
    echo -e "${BOLD}Usage:${RESET} $0 <target> [autoWin options]"
    echo -e "  ${CYAN}CIDR:  ${RESET} $0 10.100.1.0/24 -u admin -p pass -EXPLOIT"
    echo -e "  ${CYAN}Range: ${RESET} $0 10.100.1.0-10.100.8.0 -u admin -p pass"
    echo -e "  ${CYAN}List:  ${RESET} $0 10.100.62.41,10.100.62.43 -u admin -p pass"
    echo -e "  ${CYAN}Single:${RESET} $0 10.100.62.41 -u admin -p pass"
    exit 1
}

ip_to_int() {
    local ip="$1"
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

int_to_ip() {
    local n="$1"
    echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"
}

cidr_hosts() {
    local cidr="$1"
    local network="${cidr%/*}"
    local prefix="${cidr#*/}"
    local net_int
    net_int=$(ip_to_int "$network")
    local host_bits=$(( 32 - prefix ))
    local num_hosts=$(( (1 << host_bits) - 2 ))
    if (( num_hosts <= 0 )); then
        int_to_ip "$net_int"
        return
    fi
    local first=$(( net_int + 1 ))
    local last=$(( net_int + num_hosts ))
    for (( i = first; i <= last; i++ )); do
        int_to_ip "$i"
    done
}

range_hosts() {
    local start="$1"
    local end="$2"
    local start_int end_int
    start_int=$(ip_to_int "$start")
    end_int=$(ip_to_int "$end")
    if (( start_int > end_int )); then
        echo -e "${RED}[!] Error: start IP is greater than end IP${RESET}" >&2
        exit 1
    fi
    for (( i = start_int; i <= end_int; i++ )); do
        int_to_ip "$i"
    done
}


[[ $# -lt 1 ]] && usage

TARGET="$1"
shift
AUTOWIN_ARGS=("$@")


declare -a IPS

if [[ "$TARGET" == */* ]]; then
    mapfile -t IPS < <(cidr_hosts "$TARGET")
elif [[ "$TARGET" == *-* ]]; then
    START_IP="${TARGET%-*}"
    END_IP="${TARGET#*-}"
    mapfile -t IPS < <(range_hosts "$START_IP" "$END_IP")
elif [[ "$TARGET" == *,* ]]; then
    IFS=',' read -ra IPS <<< "$TARGET"
else
    IPS=("$TARGET")
fi

TOTAL=${#IPS[@]}

echo -e "${BOLD}${CYAN}────────────────────────────────────────${RESET}"
echo -e "${BOLD}[*]${RESET} Targets resolved: ${CYAN}${TOTAL} IPs${RESET}"
echo -e "${BOLD}[*]${RESET} autoWin args:     ${DIM}${AUTOWIN_ARGS[*]:-<none>}${RESET}"
echo -e "${BOLD}${CYAN}────────────────────────────────────────${RESET}"


PASS=0
FAIL=0
SKIP=0

for ip in "${IPS[@]}"; do
    if ! ping -c 1 -W 1 "$ip" &>/dev/null; then
        echo -e "${DIM}[-] $ip  →  unreachable, skipping${RESET}"
        (( SKIP++ )) || true
        continue
    fi

    echo -e "${YELLOW}[~]${RESET} ${BOLD}$ip${RESET}  →  running autoWin..."
    if autoWin "$ip" "${AUTOWIN_ARGS[@]:-}"; then
        echo -e "${GREEN}[+]${RESET} ${BOLD}$ip${RESET}  →  ${GREEN}success${RESET}"
        (( PASS++ )) || true
    else
        echo -e "${RED}[!]${RESET} ${BOLD}$ip${RESET}  →  ${RED}failed${RESET}"
        (( FAIL++ )) || true
    fi
done


echo -e "${BOLD}${CYAN}────────────────────────────────────────${RESET}"
echo -e "${BOLD}[*] Done.${RESET}  Total: ${CYAN}${TOTAL}${RESET}  |  Success: ${GREEN}${PASS}${RESET}  |  Failed: ${RED}${FAIL}${RESET}  |  Skipped: ${DIM}${SKIP}${RESET}"