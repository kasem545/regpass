#!/usr/bin/env bash
# =============================================================================
# regpass.sh — Password Wordlist Filter & Generator
# =============================================================================
# Modes:
#   1) filter   — Filter passwords from a wordlist by policy
#   2) generate — Generate random passwords matching policy
# Requires: bash 4.3+ (for namerefs), awk, tr, /dev/urandom
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[0;32m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
    BLUE=$'\033[0;34m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; DIM=''; RESET=''; BLUE=''
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
err()  { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
warn() { echo -e "${YELLOW}[WARN]${RESET}  $*" >&2; }
info() { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()   { echo -e "${GREEN}[OK]${RESET}    $*"; }

banner() {
    echo -e "${BOLD}${BLUE}"
    echo '╔═══════════════════════════════════════╗'
    echo '║       regpass — Password Filter       ║'
    echo '╚═══════════════════════════════════════╝'
    echo -e "${RESET}"
}

# ── Prompt helpers (no eval — uses bash 4.3 namerefs) ────────────────────────
prompt_var() {
    local -n _pv_ref=$1
    local _pv_prompt=$2 _pv_default=$3
    read -r -p "${BOLD}${_pv_prompt}${RESET} [${DIM}${_pv_default}${RESET}]: " _pv_input
    _pv_ref="${_pv_input:-$_pv_default}"
}

prompt_yesno() {
    local -n _yn_ref=$1
    local _yn_prompt=$2 _yn_default=$3
    while true; do
        read -r -p "${BOLD}${_yn_prompt}${RESET} [${DIM}${_yn_default}${RESET}] (yes/no): " _yn_input
        _yn_input="${_yn_input:-$_yn_default}"
        case "${_yn_input,,}" in
            yes|y) _yn_ref="yes"; return ;;
            no|n)  _yn_ref="no";  return ;;
            *) warn "Please enter 'yes' or 'no'." ;;
        esac
    done
}

prompt_int() {
    local -n _pi_ref=$1
    local _pi_prompt=$2 _pi_default=$3
    local _pi_min=${4:-0} _pi_max=${5:-999999}
    while true; do
        read -r -p "${BOLD}${_pi_prompt}${RESET} [${DIM}${_pi_default}${RESET}]: " _pi_input
        _pi_input="${_pi_input:-$_pi_default}"
        if [[ "$_pi_input" =~ ^[0-9]+$ ]] && (( _pi_input >= _pi_min && _pi_input <= _pi_max )); then
            _pi_ref="$_pi_input"; return
        fi
        warn "Enter an integer between ${_pi_min} and ${_pi_max}."
    done
}

# ── Entropy estimate: bits = length × log2(charset_size) ─────────────────────
entropy_bits() {
    local length=$1 charset=0
    [[ "$REQUIRE_LOWERCASE" == "yes" ]] && (( charset += 26 ))
    [[ "$REQUIRE_UPPERCASE" == "yes" ]] && (( charset += 26 ))
    [[ "$REQUIRE_DIGIT"     == "yes" ]] && (( charset += 10 ))
    [[ "$REQUIRE_SPECIAL"   == "yes" ]] && (( charset += 32 ))
    (( charset == 0 )) && charset=26
    awk "BEGIN { printf \"%.1f\", $length * log($charset)/log(2) }"
}

# ── Strength label from entropy bits ─────────────────────────────────────────
strength_label() {
    local bits_int=${1%.*}
    if   (( bits_int < 28 )); then echo -e "${RED}Very Weak${RESET}"
    elif (( bits_int < 36 )); then echo -e "${RED}Weak${RESET}"
    elif (( bits_int < 60 )); then echo -e "${YELLOW}Fair${RESET}"
    elif (( bits_int < 80 )); then echo -e "${GREEN}Strong${RESET}"
    else                           echo -e "${GREEN}${BOLD}Very Strong${RESET}"
    fi
}

# ── Build awk condition string — single pass, no eval+grep pipeline ───────────
build_awk_filter() {
    local min=$1 max=$2 uc=$3 lc=$4 dg=$5 sp=$6 excl=${7:-}
    local cond="length >= $min && length <= $max"
    [[ "$uc" == "yes" ]] && cond+=' && /[A-Z]/'
    [[ "$lc" == "yes" ]] && cond+=' && /[a-z]/'
    [[ "$dg" == "yes" ]] && cond+=' && /[0-9]/'
    [[ "$sp" == "yes" ]] && cond+=' && /[^a-zA-Z0-9]/'
    [[ -n  "$excl"  ]] && cond+="  && !/$excl/"
    echo "$cond"
}

# ── Random password generator (policy-verified, /dev/urandom source) ─────────
generate_password() {
    local length=$1 charset="" attempts=0 pw=""
    [[ "$REQUIRE_LOWERCASE" == "yes" ]] && charset+="abcdefghijklmnopqrstuvwxyz"
    [[ "$REQUIRE_UPPERCASE" == "yes" ]] && charset+="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    [[ "$REQUIRE_DIGIT"     == "yes" ]] && charset+="0123456789"
    [[ "$REQUIRE_SPECIAL"   == "yes" ]] && charset+='!@#$%^&*()_+-=[]{}|;:,.<>?'
    [[ -z "$charset" ]] && charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    while true; do
        (( attempts++ ))
        pw=$(LC_ALL=C tr -dc "$charset" </dev/urandom 2>/dev/null | head -c "$length") || true
        local ok=1
        [[ "$REQUIRE_UPPERCASE" == "yes" ]] && [[ ! "$pw" =~ [A-Z]         ]] && ok=0
        [[ "$REQUIRE_LOWERCASE" == "yes" ]] && [[ ! "$pw" =~ [a-z]         ]] && ok=0
        [[ "$REQUIRE_DIGIT"     == "yes" ]] && [[ ! "$pw" =~ [0-9]         ]] && ok=0
        [[ "$REQUIRE_SPECIAL"   == "yes" ]] && [[ ! "$pw" =~ [^a-zA-Z0-9] ]] && ok=0
        [[ ${#pw} -ne "$length"          ]]                                    && ok=0
        (( ok )) && { echo "$pw"; return; }
        (( attempts > 1000 )) && { err "Could not generate valid password after 1000 attempts"; return 1; }
    done
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
banner

# ── Mode selection ────────────────────────────────────────────────────────────
echo -e "${BOLD}Select mode:${RESET}"
echo -e "  ${GREEN}1)${RESET} filter   — Filter passwords from a wordlist"
echo -e "  ${GREEN}2)${RESET} generate — Generate random passwords matching policy"
echo ""
read -r -p "${BOLD}Mode${RESET} [${DIM}1${RESET}]: " _mode_in
MODE="${_mode_in:-1}"
case "$MODE" in
    1|filter)   MODE="filter"   ;;
    2|generate) MODE="generate" ;;
    *) err "Invalid mode. Choose 1 (filter) or 2 (generate)."; exit 1 ;;
esac

echo ""
echo -e "${BOLD}${CYAN}── Password Policy ─────────────────────────────${RESET}"

prompt_int    MIN_LENGTH        "Minimum password length"          8    1  256
prompt_int    MAX_LENGTH        "Maximum password length"          64   "$MIN_LENGTH"  1024
prompt_yesno  REQUIRE_UPPERCASE "Require uppercase letters (A-Z)" yes
prompt_yesno  REQUIRE_LOWERCASE "Require lowercase letters (a-z)" yes
prompt_yesno  REQUIRE_DIGIT     "Require digits (0-9)"            yes
prompt_yesno  REQUIRE_SPECIAL   "Require special characters"      yes

echo ""
echo -e "${BOLD}${CYAN}── Output Options ──────────────────────────────${RESET}"
prompt_yesno  SHOW_COUNT  "Show match/count summary"  yes
prompt_yesno  SAVE_OUTPUT "Save results to file"       no

OUTPUT_FILE=""
if [[ "$SAVE_OUTPUT" == "yes" ]]; then
    read -e -i "results.txt" -p "${BOLD}Output file${RESET} [${DIM}results.txt${RESET}]: " OUTPUT_FILE
    OUTPUT_FILE="${OUTPUT_FILE:-results.txt}"
fi

EXCLUDE_PATTERN=""
prompt_yesno USE_EXCLUDE "Exclude passwords matching a regex?" no
if [[ "$USE_EXCLUDE" == "yes" ]]; then
    read -r -p "${BOLD}Exclusion regex${RESET}: " EXCLUDE_PATTERN
fi

# ═══════════════════════════════════════════════════════
# MODE: filter — read wordlist, apply awk policy filter
# ═══════════════════════════════════════════════════════
if [[ "$MODE" == "filter" ]]; then
    echo ""
    echo -e "${BOLD}${CYAN}── Wordlist ─────────────────────────────────────${RESET}"
    read -e -i "" -p "${BOLD}Path to wordlist file${RESET}: " WORDLIST
    WORDLIST="${WORDLIST:-}"
    [[ -z "$WORDLIST" ]] && { err "No wordlist specified."; exit 1; }
    [[ ! -f "$WORDLIST" ]] && { err "File not found: $WORDLIST"; exit 1; }
    [[ ! -r "$WORDLIST" ]] && { err "Cannot read file: $WORDLIST"; exit 1; }

    TOTAL_LINES=$(wc -l < "$WORDLIST" | tr -d ' ')
    info "Wordlist: ${BOLD}${WORDLIST}${RESET} (${TOTAL_LINES} lines)"

    AWK_COND=$(build_awk_filter "$MIN_LENGTH" "$MAX_LENGTH" \
        "$REQUIRE_UPPERCASE" "$REQUIRE_LOWERCASE" "$REQUIRE_DIGIT" "$REQUIRE_SPECIAL" \
        "$EXCLUDE_PATTERN")

    echo ""
    echo -e "${BOLD}Matching passwords:${RESET}"
    echo -e "${DIM}────────────────────────────────────────────────${RESET}"

    RESULTS=$(awk "$AWK_COND" "$WORDLIST")

    if [[ -z "$RESULTS" ]]; then
        warn "No passwords matched the policy."
    else
        echo "$RESULTS"
        if [[ "$SHOW_COUNT" == "yes" ]]; then
            MATCH_COUNT=$(echo "$RESULTS" | wc -l | tr -d ' ')
            echo ""
            echo -e "${DIM}────────────────────────────────────────────────${RESET}"
            echo -e "${GREEN}${BOLD}${MATCH_COUNT}${RESET} matched / ${BOLD}${TOTAL_LINES}${RESET} total"
            PCT=$(awk "BEGIN { printf \"%.2f\", ($MATCH_COUNT / $TOTAL_LINES) * 100 }")
            echo -e "Match rate: ${CYAN}${PCT}%${RESET}"
        fi
        if [[ -n "$OUTPUT_FILE" ]]; then
            echo "$RESULTS" > "$OUTPUT_FILE"
            ok "Results saved to: ${BOLD}${OUTPUT_FILE}${RESET}"
        fi
    fi

# ═══════════════════════════════════════════════════════
# MODE: generate — produce random policy-compliant passwords
# ═══════════════════════════════════════════════════════
elif [[ "$MODE" == "generate" ]]; then
    echo ""
    echo -e "${BOLD}${CYAN}── Generator Options ───────────────────────────${RESET}"
    prompt_int GEN_COUNT  "How many passwords to generate" 10  1  10000
    prompt_int GEN_LENGTH "Password length"                16  "$MIN_LENGTH"  "$MAX_LENGTH"

    BITS=$(entropy_bits "$GEN_LENGTH")
    STRENGTH=$(strength_label "$BITS")
    echo ""
    info "Entropy: ${BOLD}${BITS} bits${RESET}  |  Strength: ${STRENGTH}"
    echo ""
    echo -e "${BOLD}Generated passwords:${RESET}"
    echo -e "${DIM}────────────────────────────────────────────────${RESET}"

    GENERATED=""
    for (( i=1; i<=GEN_COUNT; i++ )); do
        pw=$(generate_password "$GEN_LENGTH")
        echo "$pw"
        GENERATED+="$pw"$'\n'
    done

    if [[ -n "$OUTPUT_FILE" ]]; then
        printf "%s" "$GENERATED" > "$OUTPUT_FILE"
        ok "Saved to: ${BOLD}${OUTPUT_FILE}${RESET}"
    fi
fi

# ── Policy summary ────────────────────────────────────────────────────────────
echo ""
echo -e "${DIM}Policy applied:${RESET}"
echo -e "  Length    : ${BOLD}${MIN_LENGTH}–${MAX_LENGTH}${RESET}"
echo -e "  Uppercase : ${BOLD}${REQUIRE_UPPERCASE}${RESET}"
echo -e "  Lowercase : ${BOLD}${REQUIRE_LOWERCASE}${RESET}"
echo -e "  Digits    : ${BOLD}${REQUIRE_DIGIT}${RESET}"
echo -e "  Special   : ${BOLD}${REQUIRE_SPECIAL}${RESET}"
[[ -n "$EXCLUDE_PATTERN" ]] && echo -e "  Exclude   : ${BOLD}${EXCLUDE_PATTERN}${RESET}"

echo -e "\n${GREEN}${BOLD}Done.${RESET}\n"
