#!/bin/bash
#══════════════════════════════════════════════════════════════
#
#   ██████╗ ███████╗███╗   ███╗
#   ██╔══██╗██╔════╝████╗ ████║
#   ██████╔╝█████╗  ██╔████╔██║
#   ██╔═══╝ ██╔══╝  ██║╚██╔╝██║
#   ██║     ██║     ██║ ╚═╝ ██║
#   ╚═╝     ╚═╝     ╚═╝     ╚═╝
#
#   Port Forward Manager v2.0
#
#   Telegram: https://t.me/AbrAfagh
#
#══════════════════════════════════════════════════════════════

# cron runs with PATH=/usr/bin:/bin, where iptables, ethtool, tc and sysctl (sbin) are not found: add the standard directories behind whatever is there
for _d in /usr/local/sbin /usr/local/bin /usr/sbin /sbin; do case ":$PATH:" in *":$_d:"*) ;; *) PATH="${PATH:+$PATH:}$_d" ;; esac; done; export PATH; unset _d

PFM_DIR="/etc/pfm"
USERS_DIR="$PFM_DIR/users"
PORTS_DIR="$PFM_DIR/ports"
USAGE_DIR="$PFM_DIR/usage"
MTU_DIR="$PFM_DIR/mtu"
REALM_DIR="$PFM_DIR/realm"
REALM_BIN="/usr/local/bin/realm"
HEALTH_DIR="$PFM_DIR/health"
BENCH_DIR="$PFM_DIR/bench"
TUNE_DIR="$PFM_DIR/tune"
BACKUP_DIR="$PFM_DIR/backups"
PFM_CONF="$PFM_DIR/pfm.conf"
TRAFFIC_MIN=3                                  # packets that must arrive before "none was delivered" is believed
TRAFFIC_MIN_AGE=${PFM_TRAFFIC_MIN_AGE:-60}     # shortest window (s) a traffic verdict is based on
BASELINE_AGE=${PFM_BASELINE_AGE:-120}          # `pfm sync` renews its counter snapshot at most this often
WATCH_GAP=${PFM_WATCH_GAP:-30}                 # ...and looks at the tunnels at most this often (the bot calls sync a lot)
HAPROXY_CFG="$PFM_DIR/haproxy.cfg"
LOG_FILE="/var/log/pfm.log"
# If you fork this repo, change this to your own raw URL so `pfm install`
# (which also runs on self-update) fetches YOUR version, not upstream.
PFM_REPO_RAW="${PFM_REPO_RAW:-https://raw.githubusercontent.com/parham381/PFM/main}"
# Mirrors / proxies for GitHub live in /etc/pfm/pfm.conf (survives updates), e.g.
#   PFM_REPO_RAW="https://mirror.example/parham381/PFM/main"    PFM_CURL_OPTS="--proxy socks5h://127.0.0.1:1080"
[[ -r "$PFM_CONF" ]] && source "$PFM_CONF"
PFM_VERSION="2.0"
PFM_REPO="${PFM_REPO:-$(printf '%s' "$PFM_REPO_RAW" | sed -nE 's#^https?://(.*/)?raw\.githubusercontent\.com/([^/]+/[^/]+)/.*#\2#p')}"
PFM_REPO="${PFM_REPO:-parham381/PFM}"
PFM_API="${PFM_API:-https://api.github.com/repos/$PFM_REPO}"
PFM_CURL_OPTS="${PFM_CURL_OPTS:-}"
PFM_REALM_URL="${PFM_REALM_URL:-https://github.com/zhboner/realm/releases/latest/download}"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
W='\033[1;37m'; GR='\033[0;90m'; NC='\033[0m'; B='\033[1m'
MAG='\033[0;35m'

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null; }
PFM_SELF="$(readlink -f "${BASH_SOURCE[0]:-}" 2> /dev/null)"      # "" when the text came through a pipe (curl | bash -s)
PFM_ARGS=("$@")
check_root() {    # typing `PFM` as a normal user asks sudo instead of giving up
    [[ $EUID -eq 0 ]] && return 0
    if [[ -z "${PFM_REEXEC:-}" ]] && command -v sudo > /dev/null 2>&1 && [[ -n "$PFM_SELF" && -f "$PFM_SELF" && "$PFM_SELF" != /dev/* && "$PFM_SELF" != /proc/* ]]; then
        echo -e "${GR}PFM needs root - asking sudo ...${NC}" >&2
        exec sudo env PFM_REEXEC=1 bash "$PFM_SELF" "${PFM_ARGS[@]}"
    fi
    echo -e "${R}Run as root${NC}  ${GR}(sudo -i first, or put sudo in front of the command: sudo PFM)${NC}"; exit 1
}

human_bytes() {
    local b=${1:-0}
    if (( b >= 1000000000000 )); then awk "BEGIN{printf \"%.2f TB\",$b/1000000000000}"
    elif (( b >= 1000000000 )); then awk "BEGIN{printf \"%.2f GB\",$b/1000000000}"
    elif (( b >= 1000000 )); then awk "BEGIN{printf \"%.2f MB\",$b/1000000}"
    elif (( b >= 1000 )); then awk "BEGIN{printf \"%.2f KB\",$b/1000}"
    else echo "${b} B"; fi
}

gb_to_bytes() { awk "BEGIN{printf \"%.0f\",$1*1000000000}"; }
is_ipv6() { [[ "$1" == *:* ]]; }
ipt() { is_ipv6 "$1" && echo "ip6tables" || echo "iptables"; }
# Build an ip:port (or [ipv6]:port) string for --to-destination. IPv6 needs brackets
# or the port gets silently absorbed into the address by iptables.
nat_dest() { is_ipv6 "$1" && echo "[$1]:$2" || echo "$1:$2"; }

# ═══════════════ VALIDATION / VERIFICATION ═══════════════
# "Tunnel added" must mean "tunnel works": every engine is verified after it is applied,
# and the real reason is reported when it is not.
valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( $1 <= 65535 )); }
valid_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local o; for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
valid_ipv6() { [[ "$1" =~ ^[0-9A-Fa-f:.]+$ && "$1" == *:*:* ]]; }
valid_ip() { valid_ipv4 "$1" || valid_ipv6 "$1"; }
# iptables needs an IP literal; realm/haproxy may also use a hostname
valid_dest() {
    local d="$1" method="$2"
    [[ "$d" =~ ^[0-9.]+$ ]] && { valid_ipv4 "$d"; return; }
    valid_ipv6 "$d" && return 0
    [[ "$method" != "iptables" && "$d" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]
}
valid_gb() { [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]]; }
# Port/user files are `source`d as root: refuse anything the shell would interpret
safe_text() { local bad='["$`\\]'; [[ -n "$1" && ! "$1" =~ $bad && "$1" != *$'\n'* ]]; }

# @@CHUNK helpers@@
# ═══════════════ HELPERS (v2.0) ═══════════════
confirm() {    # confirm "question" [y|n default] -> 0 = yes
    local q="$1" d="${2:-n}" a hint="(y/N)"
    [[ "$d" == y ]] && hint="(Y/n)"
    [[ "${PFM_YES:-0}" == 1 ]] && return 0
    echo -ne "  ${Y}${q} ${hint}:${NC} "
    read -r a || { echo ""; return 1; }              # input closed (cron, a pipe, ssh -T) is never a "yes"
    a="${a:-$d}"; [[ "$a" == y || "$a" == Y ]]
}
pause() { echo -ne "\n  ${GR}Enter...${NC}"; read -r; }
now_us() { local t="${EPOCHREALTIME:-}"; if [[ -n "$t" ]]; then echo "${t/[.,]/}"; else echo $(( $(date +%s%N) / 1000 )); fi; }
fl() { awk -v a="$1" -v b="$3" "BEGIN{exit !(a $2 b)}"; }          # fl 3.2 '<' 5
fmt1() { awk -v v="${1:-0}" 'BEGIN{printf "%.1f", v}'; }
fmt0() { awk -v v="${1:-0}" 'BEGIN{printf "%.0f", v}'; }
hr() { printf '%.0s─' $(seq 1 "${1:-76}"); }
# unicode sparkline of the numbers in $1; a negative number is drawn as a lost packet
spark() {
    awk -v lo="${2:-}" -v hi="${3:-}" 'BEGIN { split("▁ ▂ ▃ ▄ ▅ ▆ ▇ █", L, " ") }
        { for (i = 1; i <= NF; i++) v[n++] = $i }
        END {
            mn = 1e18; mx = -1e18
            for (i = 0; i < n; i++) if (v[i] >= 0) { if (v[i] < mn) mn = v[i]; if (v[i] > mx) mx = v[i] }
            if (lo != "") mn = lo; if (hi != "") mx = hi
            if (mx <= mn) mx = mn + 1
            for (i = 0; i < n; i++) {
                if (v[i] < 0) { printf "✗"; continue }
                k = int((v[i] - mn) / (mx - mn) * 7 + 0.5) + 1; if (k < 1) k = 1; if (k > 8) k = 8
                printf "%s", L[k]
            }
            print ""
        }' <<< "$1"
}

# ── packages: install on demand (the test tools are not part of a minimal server) ──
pkg_mgr() { local m; for m in apt-get dnf yum zypper pacman apk; do command -v "$m" > /dev/null 2>&1 && { echo "$m"; return 0; }; done; return 1; }
tool_pkg() {    # package that provides command $1 on this distribution
    local cmd="$1" pm; pm=$(pkg_mgr) || return 1
    case "$pm:$cmd" in
        apt-get:ping) echo iputils-ping ;;       *:ping) echo iputils ;;
        apt-get:mtr) echo mtr-tiny ;;            *:mtr) echo mtr ;;
        apt-get:dig) echo dnsutils ;;            dnf:dig|yum:dig|zypper:dig) echo bind-utils ;;
        apk:dig) echo bind-tools ;;              pacman:dig) echo bind ;;
        apt-get:tracepath) echo iputils-tracepath ;;  *:tracepath) echo iputils ;;
        dnf:conntrack|yum:conntrack|zypper:conntrack) echo conntrack-tools ;;
        *) echo "$cmd" ;;
    esac
}
ensure_tool() {    # ensure_tool <command> [why] - offers to install the package providing it
    local cmd="$1" why="${2:-}" pkg pm
    command -v "$cmd" > /dev/null 2>&1 && return 0
    pm=$(pkg_mgr) || { echo -e "  ${R}'$cmd' is missing and no package manager was found${NC}"; return 1; }
    pkg=$(tool_pkg "$cmd")
    confirm "'$cmd' ${why:+($why) }is not installed. Install package '$pkg' now?" y || return 1
    echo -e "  ${GR}Installing $pkg (a minute or two; Ctrl+C cancels) ...${NC}"
    case "$pm" in           # --foreground: Ctrl+C reaches the package manager instead of waiting for it to finish
        apt-get) { timeout --foreground 180 apt-get update -qq; DEBIAN_FRONTEND=noninteractive timeout --foreground 300 apt-get install -y -qq "$pkg"; } > /dev/null 2>&1 < /dev/null ;;
        dnf|yum) timeout --foreground 300 "$pm" install -y -q "$pkg" > /dev/null 2>&1 < /dev/null ;;
        zypper)  timeout --foreground 300 zypper -n -q install "$pkg" > /dev/null 2>&1 < /dev/null ;;
        pacman)  timeout --foreground 300 pacman -S --noconfirm --needed "$pkg" > /dev/null 2>&1 < /dev/null ;;
        apk)     timeout --foreground 300 apk add -q "$pkg" > /dev/null 2>&1 < /dev/null ;;
    esac
    hash -r 2> /dev/null
    command -v "$cmd" > /dev/null 2>&1 && { echo -e "  ${G}$cmd installed${NC}"; return 0; }
    echo -e "  ${R}Could not install '$pkg' (internet / package mirror?)${NC}"; return 1
}

# ── GitHub access: mirrors and proxies live in /etc/pfm/pfm.conf and survive updates ──
gh_fetch() {    # curl for GitHub; PFM_CURL_OPTS (proxy etc.) is split on spaces and never glob-expanded
    local o=(); read -r -a o <<< "$PFM_CURL_OPTS"
    curl -fsSL --connect-timeout 6 --max-time "${GH_TIMEOUT:-60}" "${o[@]}" "$@"
}

SYSFS_NET="${PFM_SYSFS_NET:-/sys/class/net}"       # tests point this at a scratch tree
# ── kernel tunables through one seam (tests point PFM_SYSCTL_ROOT at a scratch tree) ──
SYSCTL_ROOT="${PFM_SYSCTL_ROOT:-/proc/sys}"
sys_path() { echo "$SYSCTL_ROOT/${1//./\/}"; }
sys_has() { [[ -e "$(sys_path "$1")" ]]; }
sys_get() { local p; p=$(sys_path "$1"); [[ -r "$p" ]] && tr '\t' ' ' < "$p" | tr -s ' ' | sed 's/ *$//'; }
sys_set() { local p; p=$(sys_path "$1"); [[ -e "$p" ]] || return 1; { printf '%s\n' "$2" > "$p"; } 2> /dev/null || return 2; }      # (braces: a refusal must not print bash's own redirection error)
# @@END helpers@@

# Name of the process that listens on a TCP port ("" = free, or ss is not installed)
port_owner() { command -v ss > /dev/null 2>&1 && ss -ltnp "sport = :$1" 2>/dev/null | grep -o 'users:((".*' | head -1; }
port_owner_name() { port_owner "$1" | sed -n 's/^users:(("\([^"]*\)".*/\1/p'; }
# Is <port> listened on by the process called <name>? (true when ss is unavailable: cannot tell)
engine_listening() {
    command -v ss > /dev/null 2>&1 || return 0
    [[ "$(port_owner_name "$1")" == "$2" ]]
}
wait_engine() {
    local i n=$(( ${3:-6} * 2 ))
    for ((i=0; i<n; i++)); do engine_listening "$1" "$2" && return 0; sleep 0.5; done
    return 1
}
dest_reachable() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

# Rule helpers: only add a rule when it is absent (keeps restore/heal idempotent)
ipt_ensure()     { local c="$1" t="$2" ch="$3"; shift 3; $c -t "$t" -C "$ch" "$@" 2>/dev/null || $c -t "$t" -A "$ch" "$@"; }
ipt_ensure_top() { local c="$1" t="$2" ch="$3"; shift 3; $c -t "$t" -C "$ch" "$@" 2>/dev/null || $c -t "$t" -I "$ch" 1 "$@"; }
# Delete every rule carrying a given comment (independent of the rule's exact spec)
ipt_del_tag() {
    local c="$1" t="$2" ch="$3" tag="$4" ln
    while ln=$($c -t "$t" -L "$ch" --line-numbers -n 2>/dev/null | grep -F "/* ${tag} */" | head -1 | awk '{print $1}'); [[ "$ln" =~ ^[0-9]+$ ]]; do
        $c -t "$t" -D "$ch" "$ln" 2>/dev/null || break
    done
}
# DROP rule for a blocked port, always on top of the chain (above any pfm_allow ACCEPT)
ipt_block_top() {
    local cmd="$1" ch="$2" p="$3" port="$4"
    while $cmd -D "$ch" -p "$p" --dport "$port" -m comment --comment "pfm_block_${port}" -j DROP 2>/dev/null; do :; done
    $cmd -I "$ch" 1 -p "$p" --dport "$port" -m comment --comment "pfm_block_${port}" -j DROP
}

# Block one iptables-engine tunnel. In FORWARD the packets are already DNAT-ed, so their port is the
# *destination* port: match the original (listen) port through conntrack instead, otherwise a
# tunnel whose destination port differs from its listen port is never actually blocked.
ipt_block_forward() {
    local cmd="$1" port="$2" p
    ipt_del_tag "$cmd" filter FORWARD "pfm_block_${port}"
    for p in tcp udp; do
        $cmd -I FORWARD 1 -p "$p" -m conntrack --ctorigdstport "$port" -m comment --comment "pfm_block_${port}" -j DROP
    done
}

# Let the tunnel through the host firewall. With a default-DROP INPUT/FORWARD policy (ufw,
# Docker, hardened images) the traffic would otherwise vanish although the tunnel looks fine.
fw_allow() {
    local port="$1" dest="$2" method="$3" dport="${4:-$1}" p cmd tag="pfm_allow_$1"
    case "$method" in
        haproxy|realm)   # local listener (IPv4) -> INPUT
            for p in tcp udp; do
                [[ "$method" == "haproxy" && "$p" == "udp" ]] && continue
                ipt_ensure_top iptables filter INPUT -p "$p" --dport "$port" -m comment --comment "$tag" -j ACCEPT 2>/dev/null
            done ;;
        *)               # DNAT-ed traffic -> FORWARD (and its replies)
            cmd=$(ipt "$dest")
            for p in tcp udp; do
                ipt_ensure_top "$cmd" filter FORWARD -p "$p" -d "$dest" --dport "$dport" -m comment --comment "$tag" -j ACCEPT 2>/dev/null
                ipt_ensure_top "$cmd" filter FORWARD -p "$p" -s "$dest" --sport "$dport" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$tag" -j ACCEPT 2>/dev/null
            done ;;
    esac
}
fw_unallow() {
    local c ch; for c in iptables ip6tables; do
        for ch in INPUT FORWARD; do ipt_del_tag "$c" filter "$ch" "pfm_allow_$1"; done
    done
}

# ═══════════════ WHO ELSE HANDLES MY PORT ═══════════════
# Another tool (a different tunnel manager, Docker, firewalld, a forgotten test rule...) can
# DNAT/REDIRECT the same port in nat PREROUTING. That runs BEFORE the packet reaches realm/haproxy
# (or pfm's own DNAT), so the tunnel looks perfect from the inside - listening, rules in place,
# loopback tests pass - while nothing from the outside ever arrives.

# `iptables-save` of one table. Within one run (sync / doctor) the listing is taken once and reused,
# so checking many tunnels does not mean dumping the whole ruleset many times.
rules_dump() {
    local k="_DUMP_${1}_${2}"
    if [[ -n "${!k+x}" ]]; then printf '%s\n' "${!k}"; else "${1}-save" -c -t "$2" 2>/dev/null; fi
}
nft_dump() { if [[ -n "${_DUMP_nft+x}" ]]; then printf '%s\n' "$_DUMP_nft"; else nft -a list ruleset 2>&1; fi; }
rules_snapshot() {
    local c t
    for c in iptables ip6tables; do
        command -v "${c}-save" > /dev/null 2>&1 || continue
        for t in mangle nat; do printf -v "_DUMP_${c}_${t}" '%s' "$("${c}-save" -c -t "$t" 2>/dev/null)"; done
    done
    command -v nft > /dev/null 2>&1 && printf -v _DUMP_nft '%s' "$(nft -a list ruleset 2>&1)"
    return 0
}
rules_snapshot_end() { unset _DUMP_iptables_mangle _DUMP_iptables_nat _DUMP_ip6tables_mangle _DUMP_ip6tables_nat _DUMP_nft; }

# Does port $P fall in an iptables/nft port list such as "80,443,9000:9999"? (neg = "!" in front)
_AWK_HIT='function hit(spec, neg,   n, a, i, r, ab, lo, hi, found) {
    n = split(spec, a, ","); found = 0
    for (i = 1; i <= n; i++) {
        r = a[i]
        if (index(r, ":")) { split(r, ab, ":"); lo = ab[1] + 0; hi = ab[2] + 0 } else { lo = r + 0; hi = lo }
        if (P + 0 >= lo && P + 0 <= hi) found = 1
    }
    return neg ? !found : found
}
'

# One TAB-separated line per rule that is not pfm's and sends <port> somewhere else:
#     <kind> <packets> <where> <rule> <command that removes it>
# <method> decides what counts: haproxy is TCP-only, and for the iptables method only a rule that
# sits BEFORE pfm's own DNAT can win (pfm appends its rule at the end of PREROUTING).
foreign_nat() {
    local port="$1" method="$2" protos="tcp,udp" own="" cmd
    [[ "$method" == "haproxy" ]] && protos="tcp"
    [[ "$method" == "iptables" && -f "$PORTS_DIR/$port" ]] && own=$( P_DEST=""; P_DPORT="$port"; source "$PORTS_DIR/$port"; nat_dest "$P_DEST" "$P_DPORT" )
    for cmd in iptables ip6tables; do
        command -v "${cmd}-save" > /dev/null 2>&1 || continue
        rules_dump "$cmd" nat | awk -v P="$port" -v PROTOS="$protos" -v OWN="$own" -v CMD="$cmd" "$_AWK_HIT"'
            BEGIN { np = split(PROTOS, pl, ","); for (i = 1; i <= np; i++) okp[pl[i]] = 1 }
            /^\[[0-9]+:[0-9]+\] -A / {
                chain = $3
                if (chain == "POSTROUTING" || chain == "OUTPUT") next
                if ($0 !~ / -j (DNAT|REDIRECT)( |$)/) next
                proto = ""; matched = 0; spec = ""; dest = ""
                for (i = 4; i <= NF; i++) {
                    if ($i == "-p" && $(i-1) != "!") proto = $(i+1)
                    else if ($i ~ /^--(dports?|destination-ports?)$/) { spec = $(i+1); if (hit(spec, $(i-1) == "!")) matched = 1 }
                    else if ($i == "--to-destination") dest = $(i+1)
                }
                if (!(proto in okp) || !matched) next
                if (OWN != "" && chain == "PREROUTING") {
                    if (spec == P && dest == OWN) { ownseen = 1; next }
                    if (ownseen) next
                }
                pk = $1; sub(/^\[/, "", pk); sub(/:.*/, "", pk)
                rule = ""; for (i = 4; i <= NF; i++) rule = rule (i > 4 ? " " : "") $i
                printf "ipt\t%s\tnat %s\t%s\t%s -t nat -D %s %s\n", pk, chain, rule, CMD, chain, rule
            }'
    done
    # rules written straight for nftables (firewalld, hand-written nft scripts). The tables that
    # iptables-nft keeps were covered above: nft announces them ("managed by iptables-nft") on
    # stderr before the listing, so read both streams and skip those tables.
    command -v nft > /dev/null 2>&1 && nft_dump | awk -v P="$port" -v PROTOS="$protos" "$_AWK_HIT"'
        BEGIN { np = split(PROTOS, pl, ","); for (i = 1; i <= np; i++) okp[pl[i]] = 1 }
        /^# Warning: table .* is managed by iptables-nft/ { managed[$4 " " $5] = 1; next }
        $1 == "table" { fam = $2; tname = $3; next }
        $1 == "chain" { chain = $2; next }
        $0 ~ /(^|[ \t])(dnat|redirect)([ \t]|$)/ && $0 ~ /dport / {
            line = $0
            if (index(line, "tcp dport ")) pr = "tcp"; else if (index(line, "udp dport ")) pr = "udp"; else pr = ""
            if (pr != "" && !(pr in okp)) next
            rest = substr(line, index(line, "dport ") + 6); neg = 0
            if (substr(rest, 1, 3) == "!= ") { neg = 1; rest = substr(rest, 4) }
            if (substr(rest, 1, 1) == "{") { spec = substr(rest, 2, index(rest, "}") - 2); gsub(/ /, "", spec) }
            else { spec = rest; sub(/[ \t].*/, "", spec) }
            gsub(/-/, ":", spec)
            if (!hit(spec, neg)) next
            pk = "-"; if (match(line, /packets [0-9]+/)) pk = substr(line, RSTART + 8, RLENGTH - 8)
            h = ""; if (match(line, /# handle [0-9]+$/)) h = substr(line, RSTART + 9)
            rule = line; sub(/[ \t]*# handle [0-9]+$/, "", rule); sub(/^[ \t]+/, "", rule); gsub(/[ \t][ \t]+/, " ", rule)
            n++; tab[n] = fam " " tname; out[n] = sprintf("nft\t%s\tnft %s %s %s\t%s\tnft delete rule %s %s %s handle %s", pk, fam, tname, chain, rule, fam, tname, chain, h)
        }
        END { for (i = 1; i <= n; i++) if (!(tab[i] in managed)) print out[i] }'
    return 0
}

# foreign_nat as readable lines (a problem report): "" = nobody else touches the port
foreign_report() {
    local port="$1" method="$2" kind pk where rule rm
    while IFS=$'\t' read -r kind pk where rule rm; do
        [[ -n "$kind" ]] || continue
        echo "  ✗ port $port is also handled by another NAT rule ($where, $pk packets) that takes the traffic before this tunnel:"
        echo "      $rule"
        echo "      remove it (back up first: iptables-save > /root/iptables.bak):  $rm"
    done < <(foreign_nat "$port" "$method")
}

# ═══════════════ DID THE TRAFFIC REACH THE TUNNEL? ═══════════════
# Two count-only rules per tunnel (they never change a packet):
#   pfm_seen_<port>  mangle PREROUTING  packets addressed to this server on <port> (before any NAT)
#   pfm_got_<port>   mangle INPUT       ... handed to the local listener (realm / haproxy); not counting
#                                       loopback, so a local `nc 127.0.0.1` test cannot hide a problem
#                    mangle FORWARD     ... forwarded by pfm's DNAT (iptables engine; matched by the
#                                       ORIGINAL port, so tunnels sharing a destination stay separate)
# "seen high, got low" is the signature of a tunnel that is perfect inside and dead outside:
# some other NAT rule, rp_filter or a firewall eats the packets in between.
traffic_rules_apply() {
    local port="$1" dest="$2" method="$3" cmd=iptables p
    [[ "$method" == "iptables" ]] && cmd=$(ipt "$dest")
    for p in tcp udp; do
        [[ "$method" == "haproxy" && "$p" == "udp" ]] && continue
        ipt_ensure "$cmd" mangle PREROUTING -p "$p" --dport "$port" -m addrtype --dst-type LOCAL -m comment --comment "pfm_seen_${port}" 2>/dev/null
        if [[ "$method" == "iptables" ]]; then
            ipt_ensure "$cmd" mangle FORWARD -p "$p" -m conntrack --ctorigdstport "$port" --ctdir ORIGINAL -m comment --comment "pfm_got_${port}" 2>/dev/null
        else
            ipt_ensure "$cmd" mangle INPUT ! -i lo -p "$p" --dport "$port" -m comment --comment "pfm_got_${port}" 2>/dev/null
        fi
    done
}
traffic_rules_remove() {
    local c; for c in iptables ip6tables; do
        ipt_del_tag "$c" mangle PREROUTING "pfm_seen_$1"
        ipt_del_tag "$c" mangle INPUT "pfm_got_$1"
        ipt_del_tag "$c" mangle FORWARD "pfm_got_$1"
    done
    rm -f "${HEALTH_DIR:?}/${1:?}"
}
# "<rules> <packets> <bytes>": how many rules carry the tag $1 in the iptables-save listing on stdin,
# and the sum of their packet / byte counters
sum_tag_pkts() {
    awk -v T="--comment $1 " '
        /^\[[0-9]+:[0-9]+\] -A / { l = $0 " "; if (index(l, T) == 0) next
            c = $1; gsub(/[\[\]]/, "", c); split(c, a, ":"); s += a[1]; b += a[2]; n++ }
        END { print n + 0, s + 0, b + 0 }'
}
# Are all count-only rules of the tunnel in place? (tcp+udp, haproxy: tcp only)
traffic_rules_ok() {
    local port="$1" dest="$2" method="$3" cmd=iptables want=2 d ns ng _
    [[ "$method" == "iptables" ]] && cmd=$(ipt "$dest")
    [[ "$method" == "haproxy" ]] && want=1
    d=$(rules_dump "$cmd" mangle)
    read -r ns _ <<< "$(sum_tag_pkts "pfm_seen_$port" <<< "$d")"
    read -r ng _ <<< "$(sum_tag_pkts "pfm_got_$port" <<< "$d")"
    (( ns >= want && ng >= want ))
}
# "<seen> <got>" since the rules were created; fails when the count-only rules are not there
traffic_counters() {
    local port="$1"; [[ -f "$PORTS_DIR/$port" ]] || return 1
    local P_DEST="" P_METHOD="iptables"; source "$PORTS_DIR/$port"
    local cmd=iptables d ns ps ng pg; [[ "$P_METHOD" == "iptables" ]] && cmd=$(ipt "$P_DEST")
    d=$(rules_dump "$cmd" mangle)
    read -r ns ps _ <<< "$(sum_tag_pkts "pfm_seen_$port" <<< "$d")"
    read -r ng pg _ <<< "$(sum_tag_pkts "pfm_got_$port" <<< "$d")"
    (( ns > 0 && ng > 0 )) || return 1
    echo "$ps $pg"
}
# "<verdict> <seen> <got> <window>" - what happened to the packets that reached this server on <port>
#   ok        packets arrived and (at least half of them) were handed to the tunnel
#   diverted  >= TRAFFIC_MIN packets never made it to the tunnel and they are the majority
#   idle      (almost) nothing arrived, cannot tell
# <window> = seconds the numbers cover; 0 = since the rules were created. Recent traffic is judged
# through the snapshot `pfm sync` (cron) keeps, so a tunnel that broke an hour ago is not hidden
# behind the packets it carried last week.
traffic_verdict() {
    local port="$1" cur seen got ts ps pg now window=0 v=idle line
    cur=$(traffic_counters "$port") || return 1
    read -r seen got <<< "$cur"
    now=$(date +%s)
    # snapshot file: line 1 = latest baseline, line 2 = the one before it ("<time> <seen> <got> ...");
    # take the newest one that is old enough to say something about recent traffic
    if [[ -r "$HEALTH_DIR/$port" ]]; then
        while read -r ts ps pg _; do
            [[ "$ts" =~ ^[0-9]+$ && "$ps" =~ ^[0-9]+$ && "$pg" =~ ^[0-9]+$ ]] || continue
            if (( now - ts >= TRAFFIC_MIN_AGE && now - ts <= 3600 && seen >= ps && got >= pg )); then
                window=$(( now - ts )); seen=$(( seen - ps )); got=$(( got - pg )); break
            fi
        done < "$HEALTH_DIR/$port"
    fi
    if (( seen - got >= TRAFFIC_MIN && got * 2 < seen )); then v=diverted
    elif (( got > 0 )); then v=ok; fi
    echo "$v $seen $got $window"
}
fmt_window() {
    if (( $1 >= 90 )); then echo "last $(( ($1 + 30) / 60 )) min"
    elif (( $1 > 0 )); then echo "last ${1}s"
    else echo "since the rules were created"; fi
}

# Problems that only show from the OUTSIDE: someone else handles the port, or packets vanish
tunnel_capture_problems() {
    local port="$1"; [[ -f "$PORTS_DIR/$port" ]] || return 0
    local P_DEST="" P_METHOD="iptables" P_BLOCKED=0; source "$PORTS_DIR/$port"
    [[ "$P_BLOCKED" == "1" ]] && return 0
    foreign_report "$port" "$P_METHOD"
    local v seen got win
    read -r v seen got win <<< "$(traffic_verdict "$port")"
    if [[ "$v" == "diverted" ]]; then
        local what="none was handed to the tunnel"; (( got > 0 )) && what="only $got of them were handed to the tunnel"
        echo "  ✗ $seen packets reached this server on port $port ($(fmt_window "$win")) but $what: another NAT rule, rp_filter or a firewall drops/diverts the rest"
    fi
    return 0
}

# ═══════════════ REALM ═══════════════
realm_installed() { [[ -x "$REALM_BIN" ]]; }
install_realm() {
    if realm_installed; then echo -e "  ${G}realm OK${NC}"; return 0; fi
    echo -e "  ${C}Installing realm...${NC}"
    local arch=$(uname -m)
    case "$arch" in
        x86_64)  arch="x86_64-unknown-linux-gnu" ;;
        aarch64) arch="aarch64-unknown-linux-gnu" ;;
        armv7l)  arch="armv7-unknown-linux-gnueabihf" ;;
        *) echo -e "  ${R}Unsupported: $arch${NC}"; return 1 ;;
    esac
    local tmp=$(mktemp -d)
    if GH_TIMEOUT=90 gh_fetch "$PFM_REALM_URL/realm-${arch}.tar.gz" -o "$tmp/realm.tar.gz" 2>/dev/null; then
        tar xzf "$tmp/realm.tar.gz" -C "$tmp/" 2>/dev/null
        if [[ -f "$tmp/realm" ]]; then
            mv "$tmp/realm" "$REALM_BIN"; chmod +x "$REALM_BIN"
            rm -rf "$tmp"; echo -e "  ${G}realm installed${NC}"; return 0
        fi
    fi
    rm -rf "$tmp"; echo -e "  ${R}Failed. Check internet.${NC}"; return 1
}
realm_conf() { echo "$REALM_DIR/${1}.toml"; }
realm_svc() { echo "pfm-realm-${1}"; }
create_realm_service() {
    local port="$1" dest="$2"; local dport="${3:-$port}" prof; mkdir -p "$REALM_DIR"
    prof=$(port_profile "$port")
    cat > "$(realm_conf "$port")" << EOF
[network]
no_tcp = false
use_udp = true
$(profile_realm_opts "$prof")

[[endpoints]]
listen = "0.0.0.0:${port}"
remote = "${dest}:${dport}"
EOF
    cat > "/etc/systemd/system/$(realm_svc "$port").service" << EOF
[Unit]
Description=PFM Realm ${port}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=20

[Service]
Type=simple
$(profile_realm_unit "$prof")
ExecStart=${REALM_BIN} -c $(realm_conf "$port")
ExecStopPost=/bin/sh -c 'sleep 1'
Restart=always
RestartSec=2
LimitNOFILE=1048576
LimitNPROC=65535
# Kill cleanly, then force after 10s
TimeoutStopSec=10
KillMode=mixed
# Prevent memory leak: auto-restart every 6h
RuntimeMaxSec=21600

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$(realm_svc "$port")" > /dev/null 2>&1
    systemctl reset-failed "$(realm_svc "$port")" 2>/dev/null
    systemctl start "$(realm_svc "$port")"
    [[ "${4:-1}" == "1" ]] || return 0
    # realm keeps running after a failed bind, so "active" proves nothing: it must own the port
    wait_engine "$port" realm 6 && return 0
    local owner; owner=$(port_owner_name "$port")
    if [[ -n "$owner" ]]; then
        echo -e "  ${R}Port ${port} is already used by '${owner}' - realm cannot listen on it.${NC}" >&2
    else
        echo -e "  ${R}realm started but is not listening on port ${port}.${NC}" >&2
        command -v journalctl > /dev/null 2>&1 && journalctl -u "$(realm_svc "$port")" -n 4 --no-pager 2>/dev/null | sed 's/^/    /' >&2
    fi
    log "REALM-NOLISTEN $port (owner: ${owner:-none})"
    return 1
}
remove_realm_service() {
    local port="$1"
    systemctl stop "$(realm_svc "$port")" 2>/dev/null
    systemctl disable "$(realm_svc "$port")" 2>/dev/null
    rm -f "/etc/systemd/system/$(realm_svc "$port").service" "$(realm_conf "$port")"
    systemctl daemon-reload
}
stop_realm_service() { systemctl stop "$(realm_svc "$1")" 2>/dev/null; }
start_realm_service() {
    systemctl enable "$(realm_svc "$1")" > /dev/null 2>&1
    systemctl restart "$(realm_svc "$1")"
}
realm_is_running() { systemctl is-active "$(realm_svc "$1")" > /dev/null 2>&1; }

# Health check: test if realm is actually forwarding (not just running)
realm_health_check() {
    local port="$1"
    [[ ! -f "$PORTS_DIR/$port" ]] && return 0
    local P_DEST="" P_METHOD="" P_BLOCKED=0; source "$PORTS_DIR/$port"
    [[ "$P_METHOD" != "realm" || "$P_BLOCKED" == "1" ]] && return 0
    if ! realm_is_running "$port"; then
        # a unit that hit its start limit refuses to start until the failed state is cleared
        systemctl reset-failed "$(realm_svc "$port")" 2>/dev/null
        start_realm_service "$port"
        log "REALM-RESTART $port (was dead)"
        return 1
    fi
    # "active" is not enough: realm stays alive after a failed bind without owning the port
    if ! engine_listening "$port" realm; then
        systemctl reset-failed "$(realm_svc "$port")" 2>/dev/null
        systemctl restart "$(realm_svc "$port")"; sleep 2
        if engine_listening "$port" realm; then log "REALM-RESTART $port (was not listening)"
        else log "REALM-NOLISTEN $port (owner: $(port_owner_name "$port"))"; fi
        return 1
    fi
    # Check if process is stuck (using too much memory or too many FDs)
    local pid=$(systemctl show -p MainPID --value "$(realm_svc "$port")" 2>/dev/null)
    if [[ -n "$pid" && "$pid" != "0" && -d "/proc/$pid" ]]; then
        local mem_kb=$(awk '/VmRSS/{print $2}' /proc/$pid/status 2>/dev/null || echo 0)
        local fds=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
        # If using >300MB RAM or >50000 FDs, restart
        if (( mem_kb > 307200 || fds > 50000 )); then
            systemctl restart "$(realm_svc "$port")"
            log "REALM-RESTART $port (mem=${mem_kb}KB fds=${fds})"
            return 1
        fi
    fi
    return 0
}

# ═══════════════ HAPROXY ═══════════════
haproxy_installed() { command -v haproxy > /dev/null 2>&1; }
install_haproxy() {
    if haproxy_installed; then echo -e "  ${G}haproxy OK${NC}"; return 0; fi
    echo -e "  ${C}Installing haproxy...${NC}"
    apt-get update -qq > /dev/null 2>&1
    apt-get install -y -qq haproxy > /dev/null 2>&1
    if haproxy_installed; then
        systemctl stop haproxy 2>/dev/null; systemctl disable haproxy 2>/dev/null
        echo -e "  ${G}haproxy installed${NC}"; return 0
    fi
    echo -e "  ${R}Failed${NC}"; return 1
}
haproxy_bin() { command -v haproxy 2>/dev/null || echo /usr/sbin/haproxy; }

# File descriptors the service can really get. Asking haproxy for more than its hard limit
# makes it refuse to start ("Cannot raise FD limit") on hosts without CAP_SYS_RESOURCE
# (LXC/OpenVZ...) - and the systemd restart loop hides it, so the port is never opened.
haproxy_nofile() {
    local lim; lim=$(awk '/Max open files/{print $5}' /proc/1/limits 2>/dev/null)
    [[ "$lim" =~ ^[0-9]+$ ]] || lim=1048576
    (( lim > 1048576 )) && lim=1048576
    echo "$lim"
}
# ~2.5 descriptors per spliced connection (2 sockets + pipe share)
haproxy_maxconn() {
    local mc=$(( ($(haproxy_nofile) - 2000) / 3 ))
    (( mc > 100000 )) && mc=100000
    (( mc < 100 )) && mc=100
    echo "$mc"
}
haproxy_header() {
    cat << EOF
global
    maxconn $(haproxy_maxconn)
    nbthread 4
    log /dev/log local0

defaults
    mode tcp
    timeout connect 5s
    timeout client 300s
    timeout server 300s
    option splice-auto

EOF
}
haproxy_stanza() {
    local port="$1" dest="$2" dport="$3" fe="" be=""
    case "$(port_profile "$port")" in    # per-tunnel profile of the Optimization Assistant
        gaming)    fe=$'    option clitcpka\n    timeout client 3600s\n'; be=$'    option srvtcpka\n    timeout connect 3s\n    timeout server 3600s\n' ;;
        bandwidth) fe=$'    option clitcpka\n    timeout client 3600s\n'; be=$'    option srvtcpka\n    timeout server 3600s\n' ;;
        multiuser) fe=$'    maxconn 20000\n    timeout client 120s\n'; be=$'    timeout server 120s\n' ;;
    esac
    printf 'frontend ft_%s\n    bind *:%s\n%s    default_backend bk_%s\n\nbackend bk_%s\n%s    server srv1 %s:%s\n\n' \
        "$port" "$port" "$fe" "$port" "$port" "$be" "$dest" "$dport"
}
# Writes /etc/systemd/system/pfm-haproxy.service; returns 0 only when its content changed
write_haproxy_unit() {
    local unit=/etc/systemd/system/pfm-haproxy.service new
    new=$(cat << EOF
[Unit]
Description=PFM HAProxy
After=network-online.target
[Service]
Type=simple
ExecStart=$(haproxy_bin) -f ${HAPROXY_CFG} -W
ExecReload=/bin/kill -USR2 \$MAINPID
Restart=always
RestartSec=3
LimitNOFILE=$(haproxy_nofile)
[Install]
WantedBy=multi-user.target
EOF
)
    [[ -f "$unit" && "$(cat "$unit")" == "$new" ]] && return 1
    printf '%s\n' "$new" > "$unit"; systemctl daemon-reload
    return 0
}
# Build the haproxy config from every haproxy tunnel and load it. The new config is validated
# first and a tunnel haproxy cannot load (unresolvable destination, port used by another
# process) is skipped and reported, so one bad tunnel never takes the good ones down.
# Returns 1 when at least one tunnel could not be loaded.
rebuild_haproxy_cfg() {
    local pf port bin; bin=$(haproxy_bin)
    local ports=() dests=() dports=() good=() bad=() i
    for pf in "$PORTS_DIR"/*; do
        [[ -f "$pf" ]] || continue
        port=$(basename "$pf")
        local P_METHOD="" P_DEST="" P_DPORT="$port" P_BLOCKED=0; source "$pf"
        [[ "$P_METHOD" != "haproxy" || "$P_BLOCKED" == "1" ]] && continue
        ports+=("$port"); dests+=("$P_DEST"); dports+=("$P_DPORT")
    done
    if [[ ${#ports[@]} -eq 0 ]]; then
        systemctl stop pfm-haproxy 2>/dev/null; rm -f "$HAPROXY_CFG"; return 0
    fi
    if [[ ! -x "$bin" ]]; then
        echo -e "  ${R}haproxy is not installed${NC}" >&2; return 1
    fi

    local owner
    for i in "${!ports[@]}"; do
        owner=$(port_owner_name "${ports[i]}")
        if [[ -n "$owner" && "$owner" != "haproxy" ]]; then
            bad+=("$i")
            echo -e "  ${R}haproxy cannot use port ${ports[i]}: already used by '${owner}'${NC}" >&2
            log "HAPROXY-REJECT ${ports[i]} (port used by $owner)"
        else good+=("$i"); fi
    done

    local tmp="$HAPROXY_CFG.new" hdr o; hdr=$(haproxy_header)
    write_cfg() { local j; { printf '%s\n\n' "$hdr"; for j in "$@"; do haproxy_stanza "${ports[j]}" "${dests[j]}" "${dports[j]}"; done; } > "$tmp"; }
    if [[ ${#good[@]} -gt 0 ]]; then
        write_cfg "${good[@]}"
        if ! o=$("$bin" -c -f "$tmp" 2>&1); then
            local ok=()
            for i in "${good[@]}"; do
                write_cfg "$i"
                if o=$("$bin" -c -f "$tmp" 2>&1); then ok+=("$i")
                else
                    bad+=("$i")
                    echo -e "  ${R}haproxy rejected tunnel :${ports[i]} -> ${dests[i]}:${dports[i]}${NC}" >&2
                    echo "$o" | grep -m2 -E 'ALERT|ERROR|could not' | sed 's/^/    /' >&2
                    log "HAPROXY-REJECT ${ports[i]} -> ${dests[i]}:${dports[i]}"
                fi
            done
            good=("${ok[@]}")
            [[ ${#good[@]} -gt 0 ]] && write_cfg "${good[@]}"
        fi
    fi
    unset -f write_cfg
    if [[ ${#good[@]} -eq 0 ]]; then
        rm -f "$tmp"; systemctl stop pfm-haproxy 2>/dev/null; rm -f "$HAPROXY_CFG"; return 1
    fi
    local same=0 allup=1
    cmp -s "$tmp" "$HAPROXY_CFG" 2>/dev/null && same=1
    mv -f "$tmp" "$HAPROXY_CFG"

    local unit_changed=0; write_haproxy_unit && unit_changed=1
    systemctl enable pfm-haproxy > /dev/null 2>&1
    for i in "${good[@]}"; do engine_listening "${ports[i]}" haproxy || allup=0; done
    if systemctl is-active pfm-haproxy > /dev/null 2>&1; then
        # a changed unit (new FD limit) only takes effect on restart; reload merely signals the master
        if (( unit_changed )); then systemctl restart pfm-haproxy
        elif (( same && allup )); then :   # nothing changed and everything is served: no needless reload
        else systemctl reload pfm-haproxy 2>/dev/null || systemctl restart pfm-haproxy; fi
    else
        systemctl reset-failed pfm-haproxy 2>/dev/null; systemctl start pfm-haproxy
    fi

    # reload always "succeeds": confirm the listeners really exist
    local t pending=()
    for ((t=0; t<12; t++)); do
        pending=()
        for i in "${good[@]}"; do engine_listening "${ports[i]}" haproxy || pending+=("${ports[i]}"); done
        [[ ${#pending[@]} -eq 0 ]] && break
        sleep 0.5
    done
    if [[ ${#pending[@]} -gt 0 ]]; then
        echo -e "  ${R}haproxy is running but not listening on: ${pending[*]}${NC}" >&2
        command -v journalctl > /dev/null 2>&1 && journalctl -u pfm-haproxy -n 4 --no-pager 2>/dev/null | sed 's/^/    /' >&2
        log "HAPROXY-NOLISTEN ${pending[*]}"
        return 1
    fi
    (( ${#bad[@]} == 0 ))
}
haproxy_is_running() { systemctl is-active pfm-haproxy > /dev/null 2>&1; }
# Cron health check: (re)load haproxy when it is down or a tunnel's port is not served
haproxy_health_check() {
    local pf port miss=0 any=0 owner
    for pf in "$PORTS_DIR"/*; do
        [[ -f "$pf" ]] || continue
        port=$(basename "$pf")
        local P_METHOD="" P_BLOCKED=0; source "$pf"
        [[ "$P_METHOD" != "haproxy" || "$P_BLOCKED" == "1" ]] && continue
        any=1
        engine_listening "$port" haproxy && continue
        owner=$(port_owner_name "$port")
        [[ -z "$owner" ]] && miss=1      # free port that haproxy should hold; a foreign owner is a conflict, not fixable here
    done
    [[ $any -eq 0 ]] && return 0
    if ! haproxy_is_running || [[ $miss -eq 1 ]]; then
        log "HAPROXY-RELOAD (service down or tunnel port not served)"
        rebuild_haproxy_cfg > /dev/null 2>&1
    fi
}

# ═══════════════ TRAFFIC ═══════════════
get_mangle_chain() {
    local port="$1"
    [[ ! -f "$PORTS_DIR/$port" ]] && { echo "FORWARD"; return; }
    local P_METHOD="iptables"; source "$PORTS_DIR/$port"
    [[ "$P_METHOD" == "iptables" ]] && echo "FORWARD" || echo "OUTPUT"
}
get_port_usage() {
    local port="$1"
    cat "$USAGE_DIR/$port" 2>/dev/null || echo 0
}
sync_port_usage() {
    local port="$1"
    [[ ! -f "$PORTS_DIR/$port" ]] && return
    local P_DEST="" P_METHOD="iptables"; source "$PORTS_DIR/$port"
    local cmd=$(ipt "$P_DEST") chain=$(get_mangle_chain "$port")
    local total=0 nums=()
    # Read counters (without zeroing)
    while IFS= read -r line; do
        if echo "$line" | grep -q "pfm_dl_${port} "; then
            local rn=$(echo "$line" | awk '{print $1}')
            local b=$(echo "$line" | awk '{print $3}')
            if [[ "$b" =~ ^[0-9]+$ && "$b" -gt 0 ]]; then
                total=$((total + b)); nums+=("$rn")
            fi
        fi
    done < <($cmd -t mangle -L "$chain" -v -n -x --line-numbers 2>/dev/null)
    # Save to file and zero only THIS port's rules
    if [[ $total -gt 0 ]]; then
        local saved=$(cat "$USAGE_DIR/$port" 2>/dev/null || echo 0)
        echo $((saved + total)) > "$USAGE_DIR/$port"
        for n in "${nums[@]}"; do $cmd -t mangle -Z "$chain" "$n" 2>/dev/null; done
    fi
}
sync_all() {
    # Prevent concurrent syncs (cron + bot + script)
    (
        flock -w 5 200 || return
        for f in "$PORTS_DIR"/*; do [[ -f "$f" ]] && sync_port_usage "$(basename "$f")"; done
    ) 200>/tmp/pfm_sync.lock
}

# ═══════════════ IPTABLES RULES ═══════════════
apply_rules_iptables() {
    local port="$1" dest="$2"; local dport="${3:-$port}"; local cmd=$(ipt "$dest") p
    for p in tcp udp; do
        ipt_ensure "$cmd" nat PREROUTING -p "$p" -m multiport --dports "$port" -j DNAT --to-destination "$(nat_dest "$dest" "$dport")"
        ipt_ensure "$cmd" nat POSTROUTING -p "$p" -m multiport --dports "$dport" -j MASQUERADE
        ipt_ensure "$cmd" mangle FORWARD -p "$p" -s "$dest" --sport "$dport" -m comment --comment "pfm_dl_${port}"
    done
}
remove_rules_iptables() {
    local port="$1" dest="$2"; local dport="${3:-$port}"; local cmd=$(ipt "$dest") p
    # The MASQUERADE rule only depends on the destination port: tunnels that share it must keep it
    local shared=0 pf op
    for pf in "$PORTS_DIR"/*; do
        [[ -f "$pf" ]] || continue; op=$(basename "$pf"); [[ "$op" == "$port" ]] && continue
        if ( P_METHOD="iptables" P_DPORT="$op" P_DEST=""; source "$pf"
             [[ "$P_METHOD" == "iptables" && "$P_DPORT" == "$dport" && "$(ipt "$P_DEST")" == "$cmd" ]] ); then
            shared=1; break
        fi
    done
    for p in tcp udp; do
        while $cmd -t nat -D PREROUTING -p "$p" -m multiport --dports "$port" -j DNAT --to-destination "$(nat_dest "$dest" "$dport")" 2>/dev/null; do :; done
        [[ $shared -eq 0 ]] && while $cmd -t nat -D POSTROUTING -p "$p" -m multiport --dports "$dport" -j MASQUERADE 2>/dev/null; do :; done
        while $cmd -t mangle -D FORWARD -p "$p" -s "$dest" --sport "$dport" -m comment --comment "pfm_dl_${port}" 2>/dev/null; do :; done
    done
}
apply_accounting_userspace() {
    local port="$1" dest="$2"; local cmd=$(ipt "$dest") p
    for p in tcp udp; do
        ipt_ensure "$cmd" mangle OUTPUT -p "$p" --sport "$port" -m comment --comment "pfm_dl_${port}"
    done
}
remove_accounting_userspace() {
    local port="$1" dest="$2"; local cmd=$(ipt "$dest") p
    for p in tcp udp; do
        while $cmd -t mangle -D OUTPUT -p "$p" --sport "$port" -m comment --comment "pfm_dl_${port}" 2>/dev/null; do :; done
    done
}
# Kernel-level rules of one tunnel (NAT / accounting / firewall allow). Idempotent.
apply_port_rules() {
    local port="$1" dest="$2" method="$3"; local dport="${4:-$port}"
    case "$method" in
        haproxy|realm) apply_accounting_userspace "$port" "$dest" ;;
        *)             apply_rules_iptables "$port" "$dest" "$dport" ;;
    esac
    fw_allow "$port" "$dest" "$method" "$dport"
    traffic_rules_apply "$port" "$dest" "$method"
    tune_apply_tunnel "$port"          # route attributes / MSS from the tunnel's profile (Optimization Assistant)
}
# Re-create those rules from scratch without touching a running realm/haproxy process.
# Repeated restores must never stack duplicate rules (that multiplies the counted traffic).
refresh_port_rules() {
    local port="$1" dest="$2" method="$3"; local dport="${4:-$port}"
    sync_port_usage "$port"      # re-adding a rule zeroes its counter: bank it first
    case "$method" in
        haproxy|realm) remove_accounting_userspace "$port" "$dest" ;;
        *)             remove_rules_iptables "$port" "$dest" "$dport" ;;
    esac
    apply_port_rules "$port" "$dest" "$method" "$dport"
}
# Is the tunnel's main kernel rule still there? (something else may have flushed iptables)
port_rules_present() {
    local port="$1"; [[ ! -f "$PORTS_DIR/$port" ]] && return 0
    local P_DEST="" P_DPORT="$port" P_METHOD="iptables"; source "$PORTS_DIR/$port"
    local cmd=$(ipt "$P_DEST")
    case "$P_METHOD" in
        haproxy|realm) $cmd -t mangle -C OUTPUT -p tcp --sport "$port" -m comment --comment "pfm_dl_${port}" 2>/dev/null ;;
        *)             $cmd -t nat -C PREROUTING -p tcp -m multiport --dports "$port" -j DNAT --to-destination "$(nat_dest "$P_DEST" "$P_DPORT")" 2>/dev/null ;;
    esac
}
apply_rules() {
    local port="$1" dest="$2" method="$3"; local dport="${4:-$port}"
    apply_port_rules "$port" "$dest" "$method" "$dport"
    case "$method" in
        haproxy) rebuild_haproxy_cfg ;;
        realm)   create_realm_service "$port" "$dest" "$dport" ;;
    esac
}
remove_rules() {
    local port="$1"; [[ ! -f "$PORTS_DIR/$port" ]] && return
    local P_DEST="" P_DPORT="$port" P_METHOD="iptables"; source "$PORTS_DIR/$port"
    case "$P_METHOD" in
        haproxy) remove_accounting_userspace "$port" "$P_DEST" ;;
        realm)   remove_accounting_userspace "$port" "$P_DEST"; remove_realm_service "$port" ;;
        *)       remove_rules_iptables "$port" "$P_DEST" "$P_DPORT" ;;
    esac
    fw_unallow "$port"
    traffic_rules_remove "$port"
    tune_remove_tunnel "$port"
    local c ch; for c in iptables ip6tables; do
        for ch in INPUT FORWARD; do ipt_del_tag "$c" filter "$ch" "pfm_block_${port}"; done
    done
}

# ═══════════════ BLOCK/UNBLOCK ═══════════════
block_port() {
    local port="$1"; [[ ! -f "$PORTS_DIR/$port" ]] && return
    local P_DEST="" P_METHOD="iptables"; source "$PORTS_DIR/$port"
    sync_port_usage "$port"; local cmd=$(ipt "$P_DEST") p
    case "$P_METHOD" in
        haproxy)
            sed -i "s/P_BLOCKED=0/P_BLOCKED=1/" "$PORTS_DIR/$port"
            rebuild_haproxy_cfg
            for p in tcp; do ipt_block_top "$cmd" INPUT "$p" "$port"; done; return ;;
        realm)
            stop_realm_service "$port"
            for p in tcp udp; do ipt_block_top "$cmd" INPUT "$p" "$port"; done ;;
        *)
            ipt_block_forward "$cmd" "$port" ;;
    esac
    sed -i "s/P_BLOCKED=0/P_BLOCKED=1/" "$PORTS_DIR/$port"
}
unblock_port() {
    local port="$1"; [[ ! -f "$PORTS_DIR/$port" ]] && return
    local P_DEST="" P_METHOD="iptables"; source "$PORTS_DIR/$port"
    local cmd=$(ipt "$P_DEST") p
    case "$P_METHOD" in
        haproxy)
            for p in tcp; do while $cmd -D INPUT -p "$p" --dport "$port" -m comment --comment "pfm_block_${port}" -j DROP 2>/dev/null; do :; done; done
            sed -i "s/P_BLOCKED=1/P_BLOCKED=0/" "$PORTS_DIR/$port"; rebuild_haproxy_cfg; return ;;
        realm)
            for p in tcp udp; do while $cmd -D INPUT -p "$p" --dport "$port" -m comment --comment "pfm_block_${port}" -j DROP 2>/dev/null; do :; done; done
            start_realm_service "$port" ;;
        *)
            ipt_del_tag "$cmd" filter FORWARD "pfm_block_${port}" ;;
    esac
    sed -i "s/P_BLOCKED=1/P_BLOCKED=0/" "$PORTS_DIR/$port"
}
check_limits() {
    for f in "$PORTS_DIR"/*; do
        [[ -f "$f" ]] || continue
        local port=$(basename "$f") P_LIMIT=0 P_BLOCKED=0 P_USER=""; source "$f"
        [[ "$P_LIMIT" -eq 0 || "$P_BLOCKED" == "1" ]] && continue
        local usage=$(cat "$USAGE_DIR/$port" 2>/dev/null || echo 0)
        (( usage >= P_LIMIT )) && { block_port "$port"; log "BLOCKED $port ($P_USER)"; }
    done
}

# ═══════════════ MTU ═══════════════
save_mtu() {
    local dev="$1" val="$2"; mkdir -p "$MTU_DIR"
    if [[ ! -f "$MTU_DIR/$dev" ]]; then
        echo -e "MTU_ORIG=\"$(ip link show "$dev" 2>/dev/null | grep -oP 'mtu \K[0-9]+')\"\nMTU_SET=\"$val\"" > "$MTU_DIR/$dev"
    else sed -i "s/MTU_SET=.*/MTU_SET=\"$val\"/" "$MTU_DIR/$dev"; fi
    ip link set mtu "$val" dev "$dev"
    local cr=$(crontab -l 2>/dev/null | grep -v "ip link set mtu.*dev $dev")
    (echo "$cr"; echo "@reboot /sbin/ip link set mtu $val dev $dev") | grep -v '^$' | crontab -
}
reset_mtu() {
    local dev="$1"
    if [[ -f "$MTU_DIR/$dev" ]]; then
        local MTU_ORIG=""; source "$MTU_DIR/$dev"
        [[ -n "$MTU_ORIG" ]] && ip link set mtu "$MTU_ORIG" dev "$dev" 2>/dev/null
        rm -f "$MTU_DIR/$dev"
    fi
    crontab -l 2>/dev/null | grep -v "ip link set mtu.*dev $dev" | crontab -
}
apply_all_mtu() {
    [[ ! -d "$MTU_DIR" ]] && return
    for f in "$MTU_DIR"/*; do [[ -f "$f" ]] || continue
        local dev=$(basename "$f") MTU_SET=""; source "$f"
        [[ -n "$MTU_SET" ]] && ip link set mtu "$MTU_SET" dev "$dev" 2>/dev/null
    done
}
remove_all_mtu() {
    [[ ! -d "$MTU_DIR" ]] && return
    for f in "$MTU_DIR"/*; do [[ -f "$f" ]] && reset_mtu "$(basename "$f")"; done
}

# ═══════════════ CLEANUP ═══════════════
cleanup_old() {
    ip -4 route flush proto "$PFM_ROUTE_PROTO" 2> /dev/null; ip -6 route flush proto "$PFM_ROUTE_PROTO" 2> /dev/null
    local c; for c in iptables ip6tables; do
        $c -D FORWARD -j PFM_ACCOUNT 2>/dev/null || true
        $c -D FORWARD -j PFM_FORWARD 2>/dev/null || true
        $c -F PFM_ACCOUNT 2>/dev/null; $c -X PFM_ACCOUNT 2>/dev/null
        $c -F PFM_FORWARD 2>/dev/null; $c -X PFM_FORWARD 2>/dev/null
        $c -t nat -D POSTROUTING -j MASQUERADE 2>/dev/null || true
        $c -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
        local chain
        for chain in FORWARD INPUT OUTPUT; do
            while $c -L $chain --line-numbers -n 2>/dev/null | grep -q "pfm_"; do
                local ln=$($c -L $chain --line-numbers -n 2>/dev/null | grep "pfm_" | head -1 | awk '{print $1}')
                [[ "$ln" =~ ^[0-9]+$ ]] && $c -D $chain "$ln" 2>/dev/null || break
            done; done
        local t; for t in "nat PREROUTING" "nat POSTROUTING"; do
            while $c -t ${t% *} -L ${t#* } --line-numbers -n 2>/dev/null | grep -q "pfm_"; do
                local ln=$($c -t ${t% *} -L ${t#* } --line-numbers -n 2>/dev/null | grep "pfm_" | head -1 | awk '{print $1}')
                [[ "$ln" =~ ^[0-9]+$ ]] && $c -t ${t% *} -D ${t#* } "$ln" 2>/dev/null || break
            done; done
        for chain in PREROUTING INPUT FORWARD OUTPUT; do
            while $c -t mangle -L $chain --line-numbers -n 2>/dev/null | grep -q "pfm_"; do
                local ln=$($c -t mangle -L $chain --line-numbers -n 2>/dev/null | grep "pfm_" | head -1 | awk '{print $1}')
                [[ "$ln" =~ ^[0-9]+$ ]] && $c -t mangle -D $chain "$ln" 2>/dev/null || break
            done; done
    done
}

header() {
    clear
    echo -e "  ${B}${C}"
    echo -e "        ██████╗ ███████╗███╗   ███╗"
    echo -e "        ██╔══██╗██╔════╝████╗ ████║"
    echo -e "        ██████╔╝█████╗  ██╔████╔██║"
    echo -e "        ██╔═══╝ ██╔══╝  ██║╚██╔╝██║"
    echo -e "        ██║     ██║     ██║ ╚═╝ ██║"
    echo -e "        ╚═╝     ╚═╝     ╚═╝     ╚═╝${NC}"
    echo -e "  ${C}──────────────────────────────────────────${NC}"
    echo -e "  ${B}${C}       PFM - Port Forward Manager v${PFM_VERSION}${NC}"
    echo -e "  ${GR}            https://t.me/AbrAfagh${NC}"
    echo -e "  ${C}──────────────────────────────────────────${NC}\n"
}

# ═══════════════ PFM-CMD (used by remote bot via SSH) ═══════════════
create_bot_cmd_helper() {
    cat > /usr/local/bin/pfm-cmd << 'CMDEOF'
#!/bin/bash
# PFM command helper for bot
PFM_DIR="/etc/pfm"
PORTS_DIR="$PFM_DIR/ports"
USAGE_DIR="$PFM_DIR/usage"

gb_to_bytes() { awk "BEGIN{printf \"%.0f\",$1*1000000000}"; }

case "$1" in
    block)
        [[ ! -f "$PORTS_DIR/$2" ]] && { echo "Port not found" >&2; exit 1; }
        /usr/local/bin/pfm sync 2>/dev/null
        source "$PORTS_DIR/$2"
        # Inline block logic
        sed -i "s/P_BLOCKED=0/P_BLOCKED=1/" "$PORTS_DIR/$2"
        case "$P_METHOD" in
            haproxy)
                for p in tcp; do
                    iptables -C INPUT -p "$p" --dport "$2" -m comment --comment "pfm_block_${2}" -j DROP 2>/dev/null || \
                    iptables -I INPUT 1 -p "$p" --dport "$2" -m comment --comment "pfm_block_${2}" -j DROP
                done
                /usr/local/bin/pfm restore 2>/dev/null ;;
            realm)
                systemctl stop "pfm-realm-${2}" 2>/dev/null
                for p in tcp udp; do
                    iptables -C INPUT -p "$p" --dport "$2" -m comment --comment "pfm_block_${2}" -j DROP 2>/dev/null || \
                    iptables -I INPUT 1 -p "$p" --dport "$2" -m comment --comment "pfm_block_${2}" -j DROP
                done ;;
            *)
                for p in tcp udp; do
                    while iptables -D FORWARD -p "$p" --dport "$2" -m comment --comment "pfm_block_${2}" -j DROP 2>/dev/null; do :; done
                    iptables -C FORWARD -p "$p" -m conntrack --ctorigdstport "$2" -m comment --comment "pfm_block_${2}" -j DROP 2>/dev/null || \
                    iptables -I FORWARD 1 -p "$p" -m conntrack --ctorigdstport "$2" -m comment --comment "pfm_block_${2}" -j DROP
                done ;;
        esac ;;
    unblock)
        [[ ! -f "$PORTS_DIR/$2" ]] && { echo "Port not found" >&2; exit 1; }
        source "$PORTS_DIR/$2"
        sed -i "s/P_BLOCKED=1/P_BLOCKED=0/" "$PORTS_DIR/$2"
        case "$P_METHOD" in
            haproxy)
                for p in tcp; do
                    while iptables -D INPUT -p "$p" --dport "$2" -m comment --comment "pfm_block_${2}" -j DROP 2>/dev/null; do :; done
                done
                /usr/local/bin/pfm restore 2>/dev/null ;;
            realm)
                for p in tcp udp; do
                    while iptables -D INPUT -p "$p" --dport "$2" -m comment --comment "pfm_block_${2}" -j DROP 2>/dev/null; do :; done
                done
                systemctl start "pfm-realm-${2}" 2>/dev/null ;;
            *)
                for p in tcp udp; do
                    while iptables -D FORWARD -p "$p" --dport "$2" -m comment --comment "pfm_block_${2}" -j DROP 2>/dev/null; do :; done
                    while iptables -D FORWARD -p "$p" -m conntrack --ctorigdstport "$2" -m comment --comment "pfm_block_${2}" -j DROP 2>/dev/null; do :; done
                done ;;
        esac ;;
    limit)
        [[ ! -f "$PORTS_DIR/$2" ]] && { echo "Port not found" >&2; exit 1; }
        nb=$(gb_to_bytes "$3")
        sed -i "s/P_LIMIT=.*/P_LIMIT=$nb/" "$PORTS_DIR/$2"
        sed -i "s/P_LIMIT_GB=.*/P_LIMIT_GB=$3/" "$PORTS_DIR/$2" ;;
    reset)
        [[ ! -f "$PORTS_DIR/$2" ]] && { echo "Port not found" >&2; exit 1; }
        echo "0" > "$USAGE_DIR/$2"
        source "$PORTS_DIR/$2"
        [[ "$P_BLOCKED" == "1" ]] && $0 unblock "$2" ;;
    addlimit)
        [[ ! -f "$PORTS_DIR/$2" ]] && { echo "Port not found" >&2; exit 1; }
        source "$PORTS_DIR/$2"
        add=$(gb_to_bytes "$3")
        new=$((P_LIMIT + add))
        newgb=$(awk "BEGIN{printf \"%.1f\",$new/1000000000}")
        sed -i "s/P_LIMIT=.*/P_LIMIT=$new/" "$PORTS_DIR/$2"
        sed -i "s/P_LIMIT_GB=.*/P_LIMIT_GB=$newgb/" "$PORTS_DIR/$2"
        [[ "$P_BLOCKED" == "1" ]] && $0 unblock "$2" ;;
    sublimit)
        [[ ! -f "$PORTS_DIR/$2" ]] && { echo "Port not found" >&2; exit 1; }
        source "$PORTS_DIR/$2"
        sub=$(gb_to_bytes "$3")
        new=$((P_LIMIT - sub))
        (( new < 0 )) && new=0
        newgb=$(awk "BEGIN{printf \"%.1f\",$new/1000000000}")
        sed -i "s/P_LIMIT=.*/P_LIMIT=$new/" "$PORTS_DIR/$2"
        sed -i "s/P_LIMIT_GB=.*/P_LIMIT_GB=$newgb/" "$PORTS_DIR/$2" ;;
    *) echo "Unknown: $1" >&2; exit 1 ;;
esac
CMDEOF
    chmod +x /usr/local/bin/pfm-cmd
}


# ═══════════════ INSTALL ═══════════════
cmd_install() {    # pfm install [--no-menu]
    check_root
    [[ "${1:-}" == --no-menu ]] && export PFM_NO_MENU=1
    header
    # This very file becomes /usr/local/bin/pfm (checked, written atomically; the version it replaces is saved for `pfm rollback`)
    install_self "$@" || exit 1
    mkdir -p "$USERS_DIR" "$PORTS_DIR" "$USAGE_DIR" "$MTU_DIR" "$REALM_DIR" "$HEALTH_DIR" "$BENCH_DIR" "$TUNE_DIR" "$BACKUP_DIR"
    install_shortcuts
    touch "$LOG_FILE"
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
    sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null 2>&1
    grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    grep -q "^net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf 2>/dev/null || echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    cat > /etc/sysctl.d/99-pfm.conf << 'SYSCTL'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096
net.core.optmem_max = 65536
net.netfilter.nf_conntrack_max = 131072
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.ipv4.tcp_max_tw_buckets = 32768
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
SYSCTL
    # Never LOWER the conntrack table (its default grows with RAM): when it is full new
    # connections are dropped, which looks exactly like "the tunnel randomly stops working"
    local ct; ct=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null)
    [[ "$ct" =~ ^[0-9]+$ ]] && (( ct > 131072 )) && sed -i '/nf_conntrack_max/d' /etc/sysctl.d/99-pfm.conf
    sysctl -p /etc/sysctl.d/99-pfm.conf > /dev/null 2>&1 || true
    modprobe tcp_bbr 2>/dev/null || true
    grep -q "tcp_bbr" /etc/modules-load.d/bbr.conf 2>/dev/null || echo "tcp_bbr" > /etc/modules-load.d/bbr.conf
    sync_all
    cleanup_old
    create_bot_cmd_helper
    (crontab -l 2>/dev/null | grep -v "pfm sync"; echo "*/5 * * * * /usr/local/bin/pfm sync > /dev/null 2>&1") | crontab -
    cat > /etc/systemd/system/pfm-restore.service << 'EOF'
[Unit]
Description=PFM Restore and Save
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/pfm restore
ExecStop=/usr/local/bin/pfm sync
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable pfm-restore.service > /dev/null 2>&1
    # cleanup_old dropped the accounting/block rules: bring every existing tunnel back in place
    cmd_restore
    echo -e "  ${G}PFM v${PFM_VERSION} installed${NC}"
    echo -e "  ${GR}From now on type${NC} ${W}PFM${NC} ${GR}anywhere on this server to open the panel.${NC}"
    log "PFM v${PFM_VERSION} installed"
    [[ "${PFM_NO_MENU:-0}" == 1 ]] || { sleep 1; cmd_menu; }
}

cmd_restore() {
    check_root
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
    sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null 2>&1
    [[ -f /etc/sysctl.d/99-pfm.conf ]] && sysctl -p /etc/sysctl.d/99-pfm.conf > /dev/null 2>&1
    apply_all_mtu
    tune_restore                       # kernel / network-card / DNS settings of the Optimization Assistant
    local need_hp=0 f
    for f in "$PORTS_DIR"/*; do
        [[ -f "$f" ]] || continue
        local port=$(basename "$f")
        local P_DEST="" P_DPORT="$port" P_METHOD="iptables" P_BLOCKED=0; source "$f"
        # Idempotent: restore also runs from the bot and after updates, never stack duplicate rules
        refresh_port_rules "$port" "$P_DEST" "$P_METHOD" "$P_DPORT"
        case "$P_METHOD" in
            haproxy) need_hp=1 ;;
            realm)   create_realm_service "$port" "$P_DEST" "$P_DPORT" 0
                     [[ "$P_BLOCKED" == "1" ]] && stop_realm_service "$port" ;;
        esac
        [[ "$P_METHOD" != "haproxy" && "$P_BLOCKED" == "1" ]] && block_port "$port"
    done
    [[ $need_hp -eq 1 ]] && rebuild_haproxy_cfg
    tune_sysctl_restore                # once more: the NAT rules above loaded nf_conntrack, so its net.netfilter.* settings exist only now
    # realm stays "active" even when it could not bind: give it a moment, then verify/restart
    sleep 2
    for f in "$PORTS_DIR"/*; do [[ -f "$f" ]] && realm_health_check "$(basename "$f")"; done
    log "Restored"
}

# Something else (ufw/docker reload, netfilter-persistent, provider scripts...) may have flushed
# our rules or disabled forwarding: put them back instead of leaving a silently dead tunnel.
heal_rules() {
    [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" == "1" ]] || {
        sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1; log "HEAL ip_forward was 0"; }
    local f port
    rules_snapshot
    for f in "$PORTS_DIR"/*; do
        [[ -f "$f" ]] || continue
        port=$(basename "$f")
        local P_DEST="" P_DPORT="$port" P_METHOD="iptables" P_BLOCKED=0; source "$f"
        traffic_rules_ok "$port" "$P_DEST" "$P_METHOD" || traffic_rules_apply "$port" "$P_DEST" "$P_METHOD"   # also installs them after an upgrade
        port_rules_present "$port" && continue
        refresh_port_rules "$port" "$P_DEST" "$P_METHOD" "$P_DPORT"
        [[ "$P_BLOCKED" == "1" && "$P_METHOD" != "haproxy" ]] && block_port "$port"
        log "HEAL $port (rules were missing)"
    done
    rules_snapshot_end
}

cmd_sync() {
    sync_all; check_limits
    [[ "$(systemctl is-system-running 2>/dev/null)" == "stopping" ]] && return
    # one run of the repair work at a time: a slow one (name lookups, a busy machine) must not pile up under the next cron run; it waits, it never skips
    if command -v flock > /dev/null 2>&1 && { exec 9> "$PFM_DIR/.sync.lock"; } 2> /dev/null; then      # (the braces keep the 2> /dev/null from silencing this process for good)
        flock -w 60 9 || log "sync: the previous run was still busy after 60 s - continuing anyway"
    fi
    heal_rules
    # Health check all realm services + haproxy
    local f
    for f in "$PORTS_DIR"/*; do
        [[ -f "$f" ]] || continue
        realm_health_check "$(basename "$f")"
    done
    haproxy_health_check
    watch_tunnels
    tune_heal                          # last: a dead engine is more urgent than a lost route attribute
}

# Keeps the counters of the previous sync and writes to the log when a tunnel starts or stops
# being diverted, or when another tool starts/stops taking its port. Logs only CHANGES.
# Snapshot file: line 1 "<time> <seen> <got> <verdict> <signature of the foreign rules, 0 = none>",
# line 2 "<time> <seen> <got>" = the baseline before it
watch_tunnels() {
    mkdir -p "$HEALTH_DIR"
    local f port now ts ps pg pv pf cur seen got v win fl fsig first older last=0
    now=$(date +%s)
    [[ -r "$HEALTH_DIR/.last" ]] && read -r last < "$HEALTH_DIR/.last"
    [[ "$last" =~ ^[0-9]+$ ]] && (( now - last < WATCH_GAP )) && return 0
    echo "$now" > "$HEALTH_DIR/.last"
    rules_snapshot
    for f in "$PORTS_DIR"/*; do
        [[ -f "$f" ]] || continue
        port=$(basename "$f")
        local P_BLOCKED=0 P_METHOD="iptables"; source "$f"
        [[ "$P_BLOCKED" == "1" ]] && { rm -f "${HEALTH_DIR:?}/${port:?}"; continue; }
        cur=$(traffic_counters "$port") || continue
        read -r seen got <<< "$cur"
        ts=0; ps=0; pg=0; pv=""; pf=0; older=""
        if [[ -r "$HEALTH_DIR/$port" ]]; then
            { read -r ts ps pg pv pf; read -r older; } < "$HEALTH_DIR/$port"
        fi
        [[ "$pf" =~ ^[0-9]+$ ]] || pf=0
        read -r v seen got win <<< "$(traffic_verdict "$port")"
        fl=$(foreign_nat "$port" "$P_METHOD"); fsig=0
        [[ -n "$fl" ]] && fsig=$(printf '%s\n' "$fl" | cut -f1,3,4 | cksum | cut -d' ' -f1)   # without the packet counter column
        if [[ "$v" == "diverted" && "$pv" != "diverted" ]]; then
            log "WARN $port: $seen packets arrived ($(fmt_window "$win")) but only $got reached the tunnel - another NAT rule, rp_filter or a firewall takes the rest (run: pfm doctor $port)"
        elif [[ "$v" == "ok" && "$pv" == "diverted" ]]; then
            log "OK $port: traffic reaches the tunnel again"
        fi
        if [[ "$fsig" != "0" && "$fsig" != "$pf" ]]; then
            first=$(printf '%s\n' "$fl" | head -1 | cut -f3,4 | tr '\t' ' ')
            log "WARN $port: another NAT rule also handles this port and runs before the tunnel: $first (run: pfm doctor $port)"
        elif [[ "$fsig" == "0" && "$pf" != "0" ]]; then
            log "OK $port: the other NAT rule that handled this port is gone"
        fi
        # keep the baseline a few minutes old: the bot calls `pfm sync` far more often than cron
        local nts="$ts" nps="$ps" npg="$pg"
        if ! [[ "$ts" =~ ^[0-9]+$ ]] || (( ts == 0 )); then
            read -r nps npg <<< "$cur"; nts=$now; older=""
        elif (( now - ts >= BASELINE_AGE )); then
            older="$ts $ps $pg"; read -r nps npg <<< "$cur"; nts=$now
        fi
        local nv="$pv"; [[ "$v" == "diverted" || "$v" == "ok" ]] && nv="$v"
        { echo "$nts $nps $npg ${nv:-idle} $fsig"; [[ -n "$older" ]] && echo "$older"; } > "$HEALTH_DIR/$port"
    done
    rules_snapshot_end
}

# ═══════════════ DIAGNOSE ═══════════════
# One line per reason why <port> does not forward. No output = the tunnel really works.
tunnel_problems() {
    local port="$1"; [[ ! -f "$PORTS_DIR/$port" ]] && return
    local P_DEST="" P_DPORT="$port" P_METHOD="iptables" P_BLOCKED=0; source "$PORTS_DIR/$port"
    [[ "$P_BLOCKED" == "1" ]] && return
    local owner
    case "$P_METHOD" in
        haproxy)
            haproxy_is_running || echo "  ✗ pfm-haproxy service is not running"
            if ! engine_listening "$port" haproxy; then
                owner=$(port_owner_name "$port")
                if [[ -n "$owner" ]]; then echo "  ✗ port $port is already used by '$owner' - haproxy cannot listen on it"
                else echo "  ✗ haproxy is not listening on port $port (config rejected? check: haproxy -c -f $HAPROXY_CFG)"; fi
            fi ;;
        realm)
            realm_is_running "$port" || echo "  ✗ service $(realm_svc "$port") is not running"
            if ! engine_listening "$port" realm; then
                owner=$(port_owner_name "$port")
                if [[ -n "$owner" ]]; then echo "  ✗ port $port is already used by '$owner' - realm cannot listen on it"
                else echo "  ✗ realm is not listening on port $port (check: journalctl -u $(realm_svc "$port") -n 20)"; fi
            fi ;;
        *)
            port_rules_present "$port" || echo "  ✗ NAT rule for port $port is missing (run: pfm restore)"
            if is_ipv6 "$P_DEST"; then
                [[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" == "1" ]] || echo "  ✗ IPv6 forwarding is disabled (net.ipv6.conf.all.forwarding=0)"
            else
                [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" == "1" ]] || echo "  ✗ IPv4 forwarding is disabled (net.ipv4.ip_forward=0)"
            fi ;;
    esac
}

# After an edit: shout when the tunnel does not actually work any more
edit_report() {
    local probs; probs=$(tunnel_problems "$1"; tunnel_capture_problems "$1")
    [[ -n "$probs" ]] && { echo -e "  ${R}Warning - the tunnel is not working:${NC}\n${R}${probs}${NC}"; sleep 3; }
    return 0
}

cmd_doctor() {
    check_root
    local only="$1" f port nbad=0 line
    echo -e "\n  ${B}${W}PFM Doctor${NC}\n  ${GR}$(printf '%.0s─' $(seq 1 60))${NC}"
    echo -e "  ${C}System${NC}"
    echo -e "    ip_forward        $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)   ${GR}(must be 1 for iptables tunnels)${NC}"
    echo -e "    FORWARD policy    $(iptables -S FORWARD 2>/dev/null | head -1)   ${GR}(DROP is fine: PFM adds its own ACCEPT rules)${NC}"
    echo -e "    INPUT policy      $(iptables -S INPUT 2>/dev/null | head -1)"
    command -v ufw > /dev/null 2>&1 && echo -e "    ufw               $(ufw status 2>/dev/null | head -1)"
    systemctl is-active docker > /dev/null 2>&1 && echo -e "    docker            ${Y}active${NC}  ${GR}(sets FORWARD to DROP)${NC}"
    if [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]]; then
        local cc cm; cc=$(cat /proc/sys/net/netfilter/nf_conntrack_count); cm=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
        local ccol="$G"; (( cc * 100 / cm >= 80 )) && ccol="$R"
        echo -e "    conntrack         ${ccol}${cc}/${cm}${NC}   ${GR}(near 100% = new connections get dropped)${NC}"
    fi
    echo -e "    realm / haproxy   $(realm_installed && echo installed || echo '-') / $(haproxy_installed && echo installed || echo '-')"
    echo -e "\n  ${C}Tunnels${NC}"
    local n=0
    rules_snapshot
    for f in "$PORTS_DIR"/*; do
        [[ -f "$f" ]] || continue
        port=$(basename "$f"); [[ -n "$only" && "$only" != "$port" ]] && continue
        local P_DEST="" P_DPORT="$port" P_METHOD="iptables" P_BLOCKED=0; source "$f"
        n=$((n+1))
        echo -e "    ${W}:${port}${NC} -> ${P_DEST}:${P_DPORT} [${P_METHOD}]"
        if [[ "$P_BLOCKED" == "1" ]]; then echo -e "      ${Y}blocked (limit reached or disabled)${NC}"; continue; fi
        local p_in p_out bad=0; p_in=$(tunnel_problems "$port"); p_out=$(tunnel_capture_problems "$port")
        if [[ -n "$p_in" ]]; then bad=1; while IFS= read -r line; do echo -e "    ${R}${line}${NC}"; done <<< "$p_in"
        else echo -e "      ${G}✓ listening / rules in place${NC}"; fi
        if [[ -n "$p_out" ]]; then bad=1; while IFS= read -r line; do echo -e "    ${R}${line}${NC}"; done <<< "$p_out"; fi
        local tv tseen tgot twin
        read -r tv tseen tgot twin <<< "$(traffic_verdict "$port")"
        case "$tv" in
            ok)   echo -e "      ${G}✓ traffic from outside reaches the tunnel${NC} ${GR}($tseen packets arrived, $tgot handed over, $(fmt_window "$twin"))${NC}" ;;
            idle) echo -e "      ${GR}- no traffic from outside seen yet ($(fmt_window "$twin")): connect from a client, then run this again${NC}" ;;
        esac
        nbad=$((nbad + bad))
        if dest_reachable "$P_DEST" "$P_DPORT"; then echo -e "      ${G}✓ destination ${P_DEST}:${P_DPORT} reachable (TCP) from this server${NC}"
        else echo -e "      ${Y}! destination ${P_DEST}:${P_DPORT} NOT reachable over TCP from this server${NC}"
             echo -e "        ${GR}wrong IP/port, destination down or blocking this server, or a UDP-only service${NC}"; fi
    done
    rules_snapshot_end
    [[ $n -eq 0 ]] && echo -e "    ${GR}No tunnels.${NC}"
    echo ""
    if [[ $nbad -eq 0 ]]; then
        echo -e "  ${G}No problem found.${NC}"
        [[ $n -gt 0 ]] && echo -e "  ${GR}The tunnel works but is slow or unstable? Measure it: ${W}pfm bench <port>${GR}  (menu: Manage Tunnels -> tunnel -> Bench Test)${NC}"
    else
        echo -e "  ${R}${nbad} tunnel(s) with problems.${NC}  ${GR}Try: pfm restore  (a foreign NAT rule listed above must be removed by you)${NC}"
    fi
    return $((nbad > 0))
}

# @@CHUNK probes@@
# ═══════════════ NETWORK PROBES (Bench Test + Optimization Assistant) ═══════════════
# Probes print "key=value" pairs on one line (nothing / err= on failure), so callers never need eval.
kvget() { local t; for t in $1; do [[ "${t%%=*}" == "$2" ]] && { echo "${t#*=}"; return 0; }; done; return 1; }

# ── ICMP latency: min/avg/p50/p95/max, jitter (mean |delta| of consecutive replies), loss, loss bursts ──
ping_summarize() {
    awk -v C="${1:-0}" '
        function isort(a, n,   i, j, t) { for (i = 2; i <= n; i++) { t = a[i]; for (j = i - 1; j >= 1 && a[j] > t; j--) a[j+1] = a[j]; a[j+1] = t } }
        BEGIN { lastseq = 0 }
        /icmp_seq=/ && /time[=<]/ {
            match($0, /icmp_seq=[0-9]+/); seq = substr($0, RSTART + 9, RLENGTH - 9) + 0
            match($0, /time[=<][0-9.]+/); t = substr($0, RSTART + 5, RLENGTH - 5) + 0
            n++; v[n] = t; s += t; sq += t * t
            if (n > 1) { d = t - prev; if (d < 0) d = -d; js += d }
            prev = t
            if (seq > lastseq + 1) { gap = seq - lastseq - 1; ev++; if (gap > mb) mb = gap }
            if (seq > lastseq) lastseq = seq
            next
        }
        /packets transmitted/ { sent = $1 + 0; if (match($0, /[0-9]+ received/)) rcv = substr($0, RSTART, RLENGTH - 9) + 0 }
        END {
            if (sent == 0) sent = C
            if (rcv == 0) rcv = n
            loss = sent > 0 ? (sent - rcv) * 100 / sent : 100
            if (n == 0) { printf "sent=%d recv=0 loss=100.00 err=noreply\n", sent; exit }
            isort(v, n)
            avg = s / n; var = sq / n - avg * avg; if (var < 0) var = 0
            p50 = v[int((n + 1) / 2)]; k = int(n * 0.95 + 0.999999); if (k < 1) k = 1; p95 = v[k]
            tail = sent - lastseq
            if (rcv < sent && tail > 0) { ev++; if (tail > mb) mb = tail }
            printf "sent=%d recv=%d loss=%.2f min=%.2f avg=%.2f p50=%.2f p95=%.2f max=%.2f jitter=%.2f stdev=%.2f lossev=%d maxburst=%d\n", \
                sent, rcv, loss, v[1], avg, p50, p95, v[n], (n > 1 ? js / (n - 1) : 0), sqrt(var), ev, mb
        }'
}
# The same statistics from an ordered list of samples (ms, or -1 = lost): one run feeds the numbers AND the sparkline
series_summary() {
    awk '
        function isort(a, n,   i, j, t) { for (i = 2; i <= n; i++) { t = a[i]; for (j = i - 1; j >= 1 && a[j] > t; j--) a[j+1] = a[j]; a[j+1] = t } }
        { for (i = 1; i <= NF; i++) { N++; if ($i >= 0) { n++; v[n] = $i; s += $i; sq += $i * $i
                if (n > 1 && prevok) { d = $i - prev; if (d < 0) d = -d; js += d; jn++ }
                prev = $i; prevok = 1; if (run > 0) { ev++; if (run > mb) mb = run; run = 0 } }
            else { run++; prevok = 0 } } }
        END {
            if (run > 0) { ev++; if (run > mb) mb = run }
            if (N == 0) { print "sent=0 recv=0 loss=100.00 err=nosamples"; exit }
            if (n == 0) { printf "sent=%d recv=0 loss=100.00 err=noreply\n", N; exit }
            for (i = 1; i <= n; i++) t[i] = v[i]
            isort(t, n)
            avg = s / n; var = sq / n - avg * avg; if (var < 0) var = 0
            k = int(n * 0.95 + 0.999999); if (k < 1) k = 1
            printf "sent=%d recv=%d loss=%.2f min=%.2f avg=%.2f p50=%.2f p95=%.2f max=%.2f jitter=%.2f stdev=%.2f lossev=%d maxburst=%d\n", \
                N, n, (N - n) * 100 / N, t[1], avg, t[int((n + 1) / 2)], t[k], t[n], (jn > 0 ? js / jn : 0), sqrt(var), ev, mb
        }' <<< "$1"
}
probe_ping() {    # probe_ping <ip> [count] [interval]
    local host="$1" count="${2:-20}" iv="${3:-0.2}" fam="" tmo
    command -v ping > /dev/null 2>&1 || { echo "sent=0 recv=0 loss=100.00 err=noping"; return 1; }
    is_ipv6 "$host" && fam="-6"
    tmo=$(awk -v c="$count" -v i="$iv" 'BEGIN{printf "%d", c * i + 10}')
    LC_ALL=C timeout --foreground "$tmo" ping $fam -n -c "$count" -i "$iv" -W 2 "$host" 2> /dev/null | ping_summarize "$count"
}
# One value per probe slot, in order: ms, or -1 for a lost packet (feeds the stability sparkline)
probe_series() {    # probe_series <ip> <seconds> [per_second]
    local host="$1" secs="$2" ps="${3:-5}" fam="" n iv
    is_ipv6 "$host" && fam="-6"
    n=$(( secs * ps )); iv=$(awk -v p="$ps" 'BEGIN{printf "%.3f", 1 / p}')
    LC_ALL=C timeout --foreground $(( secs + 12 )) ping $fam -n -c "$n" -i "$iv" -W 2 "$host" 2> /dev/null | awk -v N="$n" '
        /icmp_seq=/ && /time[=<]/ { match($0, /icmp_seq=[0-9]+/); q = substr($0, RSTART + 9, RLENGTH - 9) + 0
                                    match($0, /time[=<][0-9.]+/); if (!(q in t)) t[q] = substr($0, RSTART + 5, RLENGTH - 5) + 0 }
        END { for (i = 1; i <= N; i++) printf "%s ", (i in t) ? t[i] : "-1"; print "" }'
}
series_windows() {    # "<values>" <window size> -> average per window (-1 = whole window lost)
    awk -v W="$2" '{ for (i = 1; i <= NF; i++) { k = int((i - 1) / W); last = k; if ($i >= 0) { s[k] += $i; c[k]++ } } }
        END { for (k = 0; k <= last; k++) printf "%s ", (c[k] > 0) ? sprintf("%.2f", s[k] / c[k]) : "-1"; print "" }' <<< "$1"
}
series_stats() {    # "<values>" -> med= spikes= (samples above max(3 x median, median + 30 ms))
    awk '{ for (i = 1; i <= NF; i++) if ($i >= 0) { n++; v[n] = $i; s[n] = $i } }
        END {
            if (n == 0) { print "med=0.00 spikes=0"; exit }
            for (i = 2; i <= n; i++) { t = s[i]; for (j = i - 1; j >= 1 && s[j] > t; j--) s[j+1] = s[j]; s[j+1] = t }
            med = s[int((n + 1) / 2)]; thr = (3 * med > med + 30) ? 3 * med : med + 30
            for (i = 1; i <= n; i++) if (v[i] > thr) sp++
            printf "med=%.2f spikes=%d\n", med, sp
        }' <<< "$1"
}

# ── TCP handshake time to host:port (works when ICMP is filtered; proves the port is open end to end) ──
probe_tcp() {    # probe_tcp <ip> <port> [count]
    local host="$1" port="$2" n="${3:-10}" i t0 t1 ok=0 base=999999999 b vals=""
    for i in 1 2 3; do t0=$(now_us); timeout --foreground 3 bash -c ':'; t1=$(now_us); b=$(( t1 - t0 )); (( b < base )) && base=$b; done
    for ((i = 0; i < n; i++)); do
        t0=$(now_us)
        if timeout --foreground 3 bash -c "exec 3<>/dev/tcp/$host/$port" 2> /dev/null; then
            t1=$(now_us); ok=$(( ok + 1 )); vals="$vals $(( t1 - t0 - base ))"
        fi
        sleep 0.15
    done
    awk -v n="$n" -v ok="$ok" '{ for (i = 1; i <= NF; i++) { x = $i / 1000; if (x < 0.05) x = 0.05; c++; v[c] = x; s += x
            if (c == 1 || x < mn) mn = x; if (x > mx) mx = x; if (c > 1) { d = x - p; if (d < 0) d = -d; js += d } p = x } }
        END { if (c == 0) { printf "ok=0 n=%d\n", n; exit }
              printf "ok=%d n=%d min=%.2f avg=%.2f max=%.2f jitter=%.2f\n", ok, n, mn, s / c, mx, (c > 1 ? js / (c - 1) : 0) }' <<< "$vals"
}
# What the kernel itself saw on a real connection: MSS, path MTU, handshake RTT, congestion control
probe_conn_info() {    # probe_conn_info <ip> <port> - what the kernel saw on a connection OPENED BY THIS CALL (not another socket to the same destination)
    local host="$1" port="$2" out dst="$1"
    command -v ss > /dev/null 2>&1 || return 1
    is_ipv6 "$host" && dst="[$host]"
    # a SYN that is silently dropped must not hold the test up for two minutes (timeout), and a refusal must not print the address on the terminal
    out=$(timeout --foreground 5 bash -c 'exec 2> /dev/null 7<> "/dev/tcp/$1/$2" || exit 1
        ss -tnip state established "( dst $3 and dport = :$2 )" 2> /dev/null | awk -v pid="$$" "index(\$0, \"pid=\" pid \",\") { f = 1; next } f { print; exit }"' _ "$host" "$port" "$dst") || return 1
    awk '{ for (i = 1; i <= NF; i++) {
                    if ($i ~ /^mss:/)  { sub(/^mss:/, "", $i);  mss = $i }
                    if ($i ~ /^pmtu:/) { sub(/^pmtu:/, "", $i); pmtu = $i }
                    if ($i ~ /^rtt:/)  { sub(/^rtt:/, "", $i);  split($i, r, "/"); rtt = r[1] }
                    if ($i ~ /^cwnd:/) { sub(/^cwnd:/, "", $i); cwnd = $i }
                    if ($i ~ /^(bbr|cubic|reno|bic|htcp|vegas|westwood|hybla|yeah|illinois|lp|dctcp|cdg)$/) cc = $i }
                  }
         END { if (mss != "") printf "mss=%s pmtu=%s krtt=%s cwnd=%s cc=%s\n", mss, pmtu, rtt, cwnd, cc }' <<< "$out"
}

# ── Path MTU: largest packet that crosses with DF set. Uses the router's "frag needed (mtu = N)" when it
#    is sent, and a binary search when it is not (a PMTUD black hole - the thing that stalls real TCP) ──
_mtu_try() {    # _mtu_try <ip> <payload> [rounds] -> 0 = got a reply; MTU_MSG = MTU a router/the kernel announced.
    local o fam="" r rounds="${3:-1}"      # Three echoes per round: ONE lost packet must never decide (it used to turn a clean path into a "black hole")
    is_ipv6 "$1" && fam="-6"; MTU_MSG=""
    for (( r = 0; r < rounds; r++ )); do
        o=$(LC_ALL=C timeout --foreground 8 ping $fam -n -c 3 -i 0.2 -W 1 -M "do" -s "$2" "$1" 2>&1)
        grep -q 'bytes from' <<< "$o" && return 0
        MTU_MSG=$(sed -n 's/.*[Mm][Tt][Uu] *[=:] *\([0-9][0-9]*\).*/\1/p' <<< "$o" | head -1)
        [[ -n "$MTU_MSG" ]] && return 1           # a router answered "too big": a real answer, not a lost packet
    done
    return 1
}
probe_mtu() {    # probe_mtu <ip> <iface_mtu>
    local host="$1" imtu="${2:-1500}" hdr=28 lo=100 hi maxp frag=0 cand pmtu floor=576 mid rel=""
    is_ipv6 "$host" && { hdr=48; floor=1280; }
    command -v ping > /dev/null 2>&1 || { echo "err=noping"; return 1; }
    maxp=$(( imtu - hdr )); (( maxp > 8972 )) && maxp=8972
    _mtu_try "$host" "$lo" 2 || { echo "icmp=blocked iface=$imtu"; return 0; }
    # the full-size probe gets three rounds before it counts as failed: a lost packet is not a black hole
    if _mtu_try "$host" "$maxp" 3; then echo "icmp=ok pmtu=$imtu iface=$imtu fragmsg=0 blackhole=0"; return 0; fi
    hi=$maxp
    if [[ "$MTU_MSG" =~ ^[0-9]+$ ]] && (( MTU_MSG < imtu && MTU_MSG > hdr + lo )); then
        frag=1; cand=$MTU_MSG
        if _mtu_try "$host" $(( cand - hdr )) 2; then echo "icmp=ok pmtu=$cand iface=$imtu fragmsg=1 blackhole=0"; return 0; fi
        hi=$(( cand - hdr ))
    fi
    while (( hi - lo > 1 )); do
        mid=$(( (lo + hi) / 2 ))
        if _mtu_try "$host" "$mid"; then lo=$mid; else hi=$mid; [[ -n "$MTU_MSG" ]] && frag=1; fi
    done
    pmtu=$(( lo + hdr ))
    # a result a couple of bytes below the interface limit means a lost packet decided the search, not the path: look once more
    if (( frag == 0 && pmtu >= imtu - 2 )) && _mtu_try "$host" "$maxp" 2; then echo "icmp=ok pmtu=$imtu iface=$imtu fragmsg=0 blackhole=0"; return 0; fi
    (( pmtu < floor )) && rel=" unreliable=1"        # no real path is that small: the replies were being lost / rate-limited, so the number means nothing
    echo "icmp=ok pmtu=$pmtu iface=$imtu fragmsg=$frag blackhole=$(( frag == 0 ? 1 : 0 ))$rel"
}

# ── Route towards a destination: egress device, its type, tunnel endpoints and encapsulation overhead ──
probe_route() {    # probe_route <ip>
    local ip="$1" fam="-4" l dev src via rmtu devmtu details kind remote loc ovh=0
    is_ipv6 "$ip" && fam="-6"
    l=$(ip $fam -o route get "$ip" 2> /dev/null | head -1)
    [[ -n "$l" ]] || return 1
    dev=$(sed -n 's/.* dev \([^ ]*\).*/\1/p' <<< "$l")
    src=$(sed -n 's/.* src \([^ ]*\).*/\1/p' <<< "$l")
    via=$(sed -n 's/.* via \([^ ]*\).*/\1/p' <<< "$l")
    rmtu=$(sed -n 's/.* mtu \(lock \)\{0,1\}\([0-9][0-9]*\).*/\2/p' <<< "$l")      # "mtu lock 1400" is what a pin of the assistant looks like
    devmtu=$(cat "$SYSFS_NET/$dev/mtu" 2> /dev/null)
    details=$(ip -d -o link show dev "$dev" 2> /dev/null)
    kind=$(awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^(gre|gretap|ip6gre|ip6gretap|ipip|sit|ip6tnl|vxlan|geneve|wireguard|veth|bridge|bond|vlan|macvlan|vti|erspan|tun|tap|dummy)$/) { print $i; exit } }' <<< "$details")
    if [[ -z "$kind" ]]; then [[ -e "$SYSFS_NET/$dev/device" ]] && kind=physical || kind=virtual; fi
    remote=$(sed -n 's/.* remote \([^ ]*\).*/\1/p' <<< "$details" | head -1)
    loc=$(sed -n 's/.* local \([^ ]*\).*/\1/p' <<< "$details" | head -1)
    case "$kind" in
        gre)       ovh=24; [[ "$details" == *okey* ]] && ovh=$((ovh + 4)); [[ "$details" == *ocsum* ]] && ovh=$((ovh + 4)) ;;
        gretap)    ovh=38; [[ "$details" == *okey* ]] && ovh=$((ovh + 4)) ;;
        ipip|sit)  ovh=20 ;;
        ip6gre)    ovh=44 ;;
        ip6gretap) ovh=58 ;;
        ip6tnl)    ovh=40 ;;
        vxlan|geneve) ovh=50 ;;
        wireguard) ovh=60; [[ "$remote" == *:* ]] && ovh=80 ;;
    esac
    echo "dev=$dev src=$src via=${via:--} kind=$kind devmtu=${devmtu:-0} routemtu=${rmtu:-0} remote=${remote:--} local=${loc:--} overhead=$ovh"
}

# ── Hop-by-hop path quality ──
probe_mtr() {    # probe_mtr <ip> [cycles] [tcp-port] -> one line per hop: hop|host|loss|snt|last|avg|best|worst|stdev
    local host="$1" cyc="${2:-10}" tport="${3:-}" args=() fam=""
    command -v mtr > /dev/null 2>&1 || return 1
    is_ipv6 "$host" && fam="-6"
    args=(-n -r -w -c "$cyc" -i 0.4 $fam)
    [[ -n "$tport" ]] && args+=(-T -P "$tport")
    LC_ALL=C timeout --foreground $(( cyc + 70 )) mtr "${args[@]}" "$host" 2> /dev/null | awk '
        $1 ~ /^[0-9]+\.\|--$/ { h = $1; sub(/\.\|--$/, "", h); l = $3; sub(/%$/, "", l)
                                printf "%s|%s|%s|%s|%s|%s|%s|%s|%s\n", h, $2, l, $4, $5, $6, $7, $8, $9 }'
}
probe_trace() {    # fallback without mtr: tracepath (hop + rtt, reports the path MTU too)
    command -v tracepath > /dev/null 2>&1 || return 1
    LC_ALL=C timeout --foreground 40 tracepath -n "$1" 2> /dev/null | awk '
        /^ *[0-9]+:/ && !/no reply/ { h = $1; sub(/:$/, "", h); gsub(/\?/, "", h); host = $2; rtt = ""
                                      for (i = 1; i <= NF; i++) if ($i ~ /ms$/) { rtt = $i; sub(/ms$/, "", rtt); break }
                                      if (h ~ /^[0-9]+$/ && rtt != "" && !(h in seen)) { seen[h] = 1; printf "%s|%s|?|?|%s|%s|%s|%s|0\n", h, host, rtt, rtt, rtt, rtt } }'
}

# ── iperf3 against the helper running on the destination (see: pfm bench-server) ──
iperf_run() {    # iperf_run <secs> <iperf3 args...> -> its output; waits and retries while the helper is still busy with an earlier test
    local secs="$1" out try; shift
    for try in 1 2 3 4 5; do
        out=$(LC_ALL=C timeout --foreground $(( secs + 15 )) iperf3 "$@" 2>&1)
        [[ "$out" == *"server is busy"* ]] || break
        sleep 2
    done
    printf '%s\n' "$out"
}
iperf_tcp() {    # iperf_tcp <ip> <port> <secs> <streams> <0|1 reverse> -> mbps= retr= (receiver side goodput)
    local host="$1" port="$2" secs="$3" par="$4" rev="${5:-0}" args out
    command -v iperf3 > /dev/null 2>&1 || { echo "err=noiperf3"; return 1; }
    args=(-c "$host" -p "$port" -t "$secs" -P "$par" -f m)
    [[ "$rev" == 1 ]] && args+=(-R)
    out=$(iperf_run "$secs" "${args[@]}")
    iperf_parse_tcp <<< "$out"
}
iperf_parse_tcp() {
    awk '/bits\/sec/ && /(sender|receiver)[ \t]*$/ {
             for (i = 1; i <= NF; i++) if ($i == "Mbits/sec") { rate = $(i-1); if ($NF == "sender") { sr = rate; retr = ($(i+1) ~ /^[0-9]+$/) ? $(i+1) : 0 } else rr = rate }
         }
         /error|unable to connect|refused|busy/ { if (!err) err = "failed" }
         END { if (rr == "" && sr == "") { print "err=" (err ? err : "noresult"); exit }
               printf "mbps=%.2f retr=%d\n", (rr != "" ? rr : sr), retr + 0 }'
}
iperf_udp() {    # iperf_udp <ip> <port> <secs> <bitrate> <payload bytes> -> mbps= jitter= lost= total= loss=
    local host="$1" port="$2" secs="$3" rate="$4" len="$5" out
    command -v iperf3 > /dev/null 2>&1 || { echo "err=noiperf3"; return 1; }
    out=$(iperf_run "$secs" -c "$host" -p "$port" -u -b "$rate" -l "$len" -t "$secs" -f m)
    awk '/receiver[ \t]*$/ && /bits\/sec/ {
             for (i = 1; i <= NF; i++) { if ($i == "Mbits/sec") m = $(i-1); if ($i == "ms") j = $(i-1); if ($i ~ /^[0-9]+\/[0-9]+$/) { split($i, a, "/"); lost = a[1]; tot = a[2] } }
         }
         END { if (tot == "" || tot + 0 <= 0) { print "err=noresult"; exit }
               printf "mbps=%.3f jitter=%.3f lost=%d total=%d loss=%.3f\n", m, j, lost, tot, lost * 100 / tot }' <<< "$out"
}
iperf_peer_ok() { LC_ALL=C timeout --foreground 10 iperf3 -c "$1" -p "$2" -t 1 -f m > /dev/null 2>&1; }

# Server -> Internet baseline (not through any tunnel): tells a slow tunnel from a slow uplink
probe_inet_speed() {
    command -v curl > /dev/null 2>&1 || return 1
    local d u
    d=$(curl -s -o /dev/null -w '%{speed_download}' --connect-timeout 4 --max-time 8 'https://speed.cloudflare.com/__down?bytes=100000000' 2> /dev/null)
    u=$(head -c 30000000 /dev/zero | curl -s -o /dev/null -w '%{speed_upload}' --connect-timeout 4 --max-time 8 -X POST --data-binary @- 'https://speed.cloudflare.com/__up' 2> /dev/null)
    awk -v d="${d:-0}" -v u="${u:-0}" 'BEGIN { if (d + 0 <= 0 && u + 0 <= 0) exit 1; printf "down=%.1f up=%.1f\n", d * 8 / 1e6, u * 8 / 1e6 }'
}

# ── Host load while a test runs ──
cpu_snap() { grep '^cpu' /proc/stat | tr '\n' ';'; }
cpu_diff() {    # cpu_diff <snap1> <snap2> -> all= (%) max= (busiest core %) maxcpu= softirq= (%, busiest core)
    awk -v A="$1" -v B="$2" 'BEGIN {
        n1 = split(A, a, ";"); split(B, b, ";"); mx = 0
        for (i = 1; i <= n1; i++) if (a[i] != "" && b[i] != "") {
            split(a[i], x, " "); split(b[i], y, " ")
            t1 = 0; t2 = 0; for (j = 2; j <= 9; j++) { t1 += x[j]; t2 += y[j] }
            dt = t2 - t1; if (dt <= 0) continue
            busy = (dt - ((y[5] + y[6]) - (x[5] + x[6]))) * 100 / dt; si = (y[8] - x[8]) * 100 / dt
            if (x[1] == "cpu") all = busy; else if (busy >= mx) { mx = busy; mc = x[1]; ms = si }
        }
        printf "all=%.1f max=%.1f maxcpu=%s softirq=%.1f\n", all, mx, (mc == "" ? "-" : mc), ms }'
}
engine_pids() {    # engine_pids <port> <method> -> pids of the engine serving the tunnel
    local m
    case "$2" in
        realm)   systemctl show -p MainPID --value "$(realm_svc "$1")" 2> /dev/null ;;
        haproxy) m=$(systemctl show -p MainPID --value pfm-haproxy 2> /dev/null); [[ "$m" =~ ^[0-9]+$ && "$m" -gt 0 ]] && echo "$m $(pgrep -P "$m" 2> /dev/null | tr '\n' ' ')" ;;
    esac
}
proc_ticks() { local t=0 p a; for p in "$@"; do [[ "$p" =~ ^[0-9]+$ && "$p" -gt 0 ]] || continue; a=$(awk '{ print $14 + $15 }' "/proc/$p/stat" 2> /dev/null); t=$(( t + ${a:-0} )); done; echo "$t"; }
nic_stat() { local d="$SYSFS_NET/$1/statistics" f; for f in rx_dropped tx_dropped rx_errors tx_errors rx_missed_errors rx_fifo_errors; do printf '%s ' "$(cat "$d/$f" 2> /dev/null || echo 0)"; done; echo; }
softnet_stat() {    # -> "<dropped> <time_squeeze>" summed over all CPUs
    local a b c d=0 s=0
    while read -r a b c; do d=$(( d + 16#${b:-0} )); s=$(( s + 16#${c:-0} )); done < <(awk '{ print $1, $2, $3 }' /proc/net/softnet_stat 2> /dev/null)
    echo "$d $s"
}
tcp_snmp() { awk '/^Tcp:/ { if (!h) { for (i = 1; i <= NF; i++) n[$i] = i; h = 1 } else print $(n["OutSegs"]), $(n["RetransSegs"]) }' /proc/net/snmp 2> /dev/null; }

# ── Traffic that really flows through a tunnel right now ──
traffic_bytes() {    # traffic_bytes <port> -> "<upload bytes> <download bytes>" (client->server, server->client)
    local port="$1"; [[ -f "$PORTS_DIR/$port" ]] || { echo "0 0"; return 1; }
    local P_DEST="" P_METHOD="iptables"; source "$PORTS_DIR/$port"
    local cmd=iptables d n up dl saved
    [[ "$P_METHOD" == "iptables" ]] && cmd=$(ipt "$P_DEST")
    d=$(rules_dump "$cmd" mangle)
    read -r n _ up <<< "$(sum_tag_pkts "pfm_got_$port" <<< "$d")"
    read -r n _ dl <<< "$(sum_tag_pkts "pfm_dl_$port" <<< "$d")"
    saved=$(cat "$USAGE_DIR/$port" 2> /dev/null || echo 0)
    echo "${up:-0} $(( ${dl:-0} + saved ))"
}
live_rate() {    # live_rate <port> [seconds] -> up= down= (Mbit/s)
    local port="$1" secs="${2:-4}" a b
    a=$(traffic_bytes "$port"); sleep "$secs"; b=$(traffic_bytes "$port")
    awk -v a="$a" -v b="$b" -v s="$secs" 'BEGIN { split(a, x, " "); split(b, y, " "); du = y[1] - x[1]; dd = y[2] - x[2]
        if (du < 0) du = 0; if (dd < 0) dd = 0; printf "up=%.2f down=%.2f\n", du * 8 / s / 1e6, dd * 8 / s / 1e6 }'
}
conn_count() {    # tracked connections whose original destination port is <port>
    if [[ -r /proc/net/nf_conntrack ]]; then
        awk -v p="dport=$1" '{ for (i = 1; i <= NF; i++) if ($i ~ /^dport=/) { if ($i == p) c++; break } } END { print c + 0 }' /proc/net/nf_conntrack
    elif command -v ss > /dev/null 2>&1; then ss -Htn state established "( sport = :$1 )" 2> /dev/null | wc -l
    else echo 0; fi
}
# @@END probes@@
# @@CHUNK bench@@
# ═══════════════ BENCH TEST ═══════════════
# What can be measured honestly from this server: the leg server -> destination (latency, jitter, loss, MTU,
# route), what the engine adds on top, how the host copes, and the traffic that really flows right now.
# The client -> server leg cannot be measured from here and is not claimed to be.
declare -A BN=()          # metrics of the running test
BN_FIND=()                # findings   "sev|text"      sev: crit warn info ok
BN_RECO=()                # actions    "id|why"        ids are handled by assist_do
BN_ABORT=0; BN_MASK=0; BN_STEP=0; BN_TOTAL=0

bn_dur() { [[ "${PFM_BENCH_FAST:-0}" == 1 ]] && echo "$2" || echo "$1"; }     # bn_dur <seconds> <seconds when PFM_BENCH_FAST=1 (tests)>
bset() { BN["$1"]="$2"; }
bget() { printf '%s' "${BN[$1]:-${2:-}}"; }
bn_kv() { local pre="$1" t; for t in $2; do BN["${pre}_${t%%=*}"]="${t#*=}"; done; }
bn_find() { BN_FIND+=("$1|$2"); }
bn_reco() { local r; for r in "${BN_RECO[@]}"; do [[ "${r%%|*}" == "$1" ]] && return 0; done; BN_RECO+=("$1|$2"); }
bn_step() { BN_STEP=$((BN_STEP + 1)); printf "  ${GR}[%d/%d]${NC} %-36s" "$BN_STEP" "$BN_TOTAL" "$1"; }
bench_kill_children() { local p; for p in $(jobs -p 2> /dev/null); do kill "$p" 2> /dev/null; done; pkill -P $$ 2> /dev/null; bench_engine_stop; return 0; }

# ── collect the facts the test is about ──
bench_prepare() {
    local port="$1" ip virt
    BN=(); BN_FIND=(); BN_RECO=(); BN_ABORT=0
    [[ -f "$PORTS_DIR/$port" ]] || return 1
    local P_DEST="" P_DPORT="$port" P_METHOD="iptables" P_USER="" P_PROFILE="" P_BLOCKED=0; source "$PORTS_DIR/$port"
    ip="$P_DEST"
    valid_ip "$ip" || ip=$(timeout 3 getent ahosts "$P_DEST" 2> /dev/null | awk '{ print $1; exit }')
    [[ -n "$ip" ]] || return 1
    bset port "$port"; bset dest "$P_DEST"; bset ip "$ip"; bset dport "$P_DPORT"; bset method "$P_METHOD"
    bset owner "$P_USER"; bset profile "${P_PROFILE:-balanced}"; bset ts "$(date +%s)"; bset ver "$PFM_VERSION"; bset blocked "${P_BLOCKED:-0}"
    bn_kv r "$(probe_route "$ip")"
    [[ -n "$(bget r_dev)" ]] || return 1
    # the MTU the kernel really uses towards this destination: a route pin of the assistant ("mtu lock N") is smaller than the interface
    local dm rm; dm=$(bget r_devmtu 0); rm=$(bget r_routemtu 0)
    [[ "$dm" =~ ^[0-9]+$ ]] || dm=0; [[ "$rm" =~ ^[0-9]+$ ]] || rm=0
    if (( rm > 0 && (dm == 0 || rm < dm) )); then bset r_effmtu "$rm"; bset r_pinned 1; else bset r_effmtu "$dm"; bset r_pinned 0; fi
    # is the tunnel itself up? (a stopped engine or a missing rule explains "0 Mbit/s live" better than any score)
    case "$P_METHOD" in
        realm|haproxy) engine_listening "$port" "$P_METHOD" && bset up 1 || bset up 0 ;;
        *)             port_rules_present "$port" && bset up 1 || bset up 0 ;;
    esac
    bset host "$(hostname -s 2> /dev/null)"
    bset os "$(. /etc/os-release 2> /dev/null; echo "${PRETTY_NAME:-$(uname -s)}")"
    bset kernel "$(uname -r)"
    virt=$(systemd-detect-virt 2> /dev/null); bset virt "${virt:-none}"           # on bare metal it prints "none" AND fails
    bset cpus "$(nproc 2> /dev/null || echo 1)"
    bset ram "$(awk '/MemTotal/ { printf "%d", $2 / 1024 }' /proc/meminfo)"
    bset load "$(cut -d' ' -f1 /proc/loadavg)"
    bset cc "$(sys_get net.ipv4.tcp_congestion_control)"
    bset qdisc "$(tc qdisc show dev "$(bget r_dev)" root 2> /dev/null | awk 'NR == 1 { print $2 }')"
    bset rmem_max "$(sys_get net.ipv4.tcp_rmem | awk '{ print $3 }')"
    bset ct_count "$(sys_get net.netfilter.nf_conntrack_count)"; bset ct_max "$(sys_get net.netfilter.nf_conntrack_max)"
    return 0
}

# ── temporary copy of the tunnel's engine in front of the helper: shows what the engine adds ──
BN_ENG_PID=""; BN_ENG_CFG=""
bench_engine_start() {    # bench_engine_start <method> <ip> <peer port> <local port> -> 0 with BN_ENG_PID set.
    local m="$1" ip="$2" pp="$3" tp="$4" dest="$2:$3" i       # Started in THIS shell (no $( )), so a signal or Ctrl+C can find and stop it.
    is_ipv6 "$ip" && dest="[$ip]:$pp"
    BN_ENG_PID=""; BN_ENG_CFG=""
    case "$m" in
        realm)   [[ -x "$REALM_BIN" ]] || return 1
                 "$REALM_BIN" -l "127.0.0.1:$tp" -r "$dest" > /dev/null 2>&1 & BN_ENG_PID=$! ;;
        haproxy) haproxy_installed || return 1
                 BN_ENG_CFG=$(mktemp "${TMPDIR:-/tmp}/pfm-bench-ha.XXXXXX") || return 1
                 printf 'global\n    maxconn 4000\ndefaults\n    mode tcp\n    timeout connect 5s\n    timeout client 60s\n    timeout server 60s\n    option splice-auto\nfrontend ft\n    bind 127.0.0.1:%s\n    default_backend bk\nbackend bk\n    server s %s\n' "$tp" "$dest" > "$BN_ENG_CFG"
                 "$(haproxy_bin)" -f "$BN_ENG_CFG" -db > /dev/null 2>&1 & BN_ENG_PID=$! ;;
        *) return 1 ;;
    esac
    for i in $(seq 1 25); do [[ -n "$(port_owner_name "$tp")" ]] && return 0; sleep 0.1; done
    bench_engine_stop; return 1
}
bench_engine_stop() {
    if [[ -n "$BN_ENG_PID" ]]; then kill "$BN_ENG_PID" 2> /dev/null; sleep 0.2; kill -9 "$BN_ENG_PID" 2> /dev/null; wait "$BN_ENG_PID" 2> /dev/null; fi
    [[ -n "$BN_ENG_CFG" ]] && rm -f "$BN_ENG_CFG"
    BN_ENG_PID=""; BN_ENG_CFG=""; return 0
}

# ── throughput suite: needs the helper running on the destination ──
bench_speed() {    # bench_speed <ip> <peer port>
    local ip="$1" pp="$2" dev method tmp lp c0 c1 n0 n1 s0 s1 t0 t1 ramp pcount piv sd
    dev=$(bget r_dev); method=$(bget method); tmp=$(mktemp)
    ramp=$(bn_dur 1.5 0.4); pcount=$(bn_dur 10 4); piv=$(bn_dur 0.5 0.3); sd=$(bn_dur 8 2); bset spd_secs "$sd"
    n0=$(nic_stat "$dev"); s0=$(softnet_stat); t0=$(tcp_snmp)
    bn_kv dl1 "$(iperf_tcp "$ip" "$pp" "$(bn_dur 6 2)" 1 1)"                       # one stream = what a single download feels like
    (( BN_ABORT )) && { rm -f "$tmp"; return; }
    c0=$(cpu_snap); ( sleep "$ramp"; probe_ping "$ip" "$pcount" "$piv" > "$tmp" ) & lp=$!       # pings while the line is full (after the ramp-up)
    bn_kv dl4 "$(iperf_tcp "$ip" "$pp" "$sd" 4 1)"                                 # four streams = the link's capacity
    c1=$(cpu_snap); wait "$lp" 2> /dev/null
    bn_kv ldl "$(cat "$tmp")"; bn_kv cpu "$(cpu_diff "$c0" "$c1")"
    (( BN_ABORT )) && { rm -f "$tmp"; return; }
    ( sleep "$ramp"; probe_ping "$ip" "$pcount" "$piv" > "$tmp" ) & lp=$!
    bn_kv ul4 "$(iperf_tcp "$ip" "$pp" "$sd" 4 0)"
    wait "$lp" 2> /dev/null; bn_kv lul "$(cat "$tmp")"
    (( BN_ABORT )) && { rm -f "$tmp"; return; }
    bn_kv udp "$(iperf_udp "$ip" "$pp" "$sd" 1M 200)"                              # game / voice-like stream
    case "$method" in
        realm|haproxy)
            local tp ep0 ep1 ta tb hz e d
            tp=$(( 20000 + RANDOM % 30000 )); while [[ -n "$(port_owner_name "$tp")" ]]; do tp=$(( 20000 + RANDOM % 30000 )); done
            if bench_engine_start "$method" "$ip" "$pp" "$tp"; then
                hz=$(getconf CLK_TCK 2> /dev/null || echo 100)
                ep0=$(proc_ticks "$BN_ENG_PID"); ta=$(now_us); c0=$(cpu_snap)
                bn_kv eng "$(iperf_tcp 127.0.0.1 "$tp" "$sd" 4 1)"
                ep1=$(proc_ticks "$BN_ENG_PID"); tb=$(now_us); c1=$(cpu_snap)
                bset eng_cpu "$(awk -v a="$ep0" -v b="$ep1" -v ta="$ta" -v tb="$tb" -v hz="$hz" 'BEGIN { d = (tb - ta) / 1e6; printf "%.0f", (d > 0 ? (b - a) / hz / d * 100 : 0) }')"
                bn_kv engc "$(cpu_diff "$c0" "$c1")"
                bench_engine_stop
                # two runs over the internet differ by 20-30% on their own: when the engine looks slow, measure the direct path once more and compare with the better one
                e=$(bget eng_mbps 0); d=$(bget dl4_mbps 0)
                if fl "$d" '>' 0 && fl "$e" '<' "$(awk -v d="$d" 'BEGIN { print d * 0.75 }')" && (( ! BN_ABORT )); then bn_kv dl4b "$(iperf_tcp "$ip" "$pp" "$sd" 4 1)"; fi
            fi ;;
    esac
    n1=$(nic_stat "$dev"); s1=$(softnet_stat); t1=$(tcp_snmp)
    bset nic_drops "$(awk -v a="$n0" -v b="$n1" 'BEGIN { split(a, x, " "); split(b, y, " "); d = (y[1] - x[1]) + (y[2] - x[2]) + (y[5] - x[5]) + (y[6] - x[6]); print d < 0 ? 0 : d }')"
    bset softnet_drops "$(awk -v a="$s0" -v b="$s1" 'BEGIN { split(a, x, " "); split(b, y, " "); print y[1] - x[1] }')"
    bset softnet_squeeze "$(awk -v a="$s0" -v b="$s1" 'BEGIN { split(a, x, " "); split(b, y, " "); print y[2] - x[2] }')"
    bset tcp_retrans_pct "$(awk -v a="$t0" -v b="$t1" 'BEGIN { split(a, x, " "); split(b, y, " "); o = y[1] - x[1]; r = y[2] - x[2]; printf "%.2f", (o > 0 ? r * 100 / o : 0) }')"
    rm -f "$tmp"
}

# ── the test ──
bench_run() {    # bench_run <port> <quick|full> [peer iperf3 port, 0 = none] [1 = also measure this server's own internet speed]
    local port="$1" mode="${2:-quick}" pport="${3:-0}" inet="${4:-0}" ip dport method dev t_start ser win secs imtu
    bench_prepare "$port" || { echo -e "  ${R}Cannot start the test: tunnel not found, destination does not resolve, or no route to it.${NC}"; return 1; }
    ip=$(bget ip); dport=$(bget dport); method=$(bget method); dev=$(bget r_dev)
    # an optional tool is asked for BEFORE the numbered steps start, where the question can be seen and answered
    command -v mtr > /dev/null 2>&1 || ensure_tool mtr "route analysis - without it tracepath is used" || true
    t_start=$(date +%s); bset mode "$mode"; bset peer "$pport"
    BN_STEP=0; BN_TOTAL=5; [[ "$mode" == full ]] && BN_TOTAL=6
    trap 'BN_ABORT=1; bench_kill_children' INT
    trap 'bench_kill_children; trap - INT TERM HUP; exit 143' TERM
    trap 'bench_kill_children; trap - INT TERM HUP; exit 129' HUP
    echo -e "\n  ${B}${W}Bench Test${NC}  ${GR}:${port} -> $(bget dest):${dport}  [${method}]  mode: ${mode}${NC}\n" | bn_out

    # 1) latency, jitter, loss, stability (one run feeds numbers and sparkline)
    secs=$(bn_dur 8 3); [[ "$mode" == full ]] && secs=$(bn_dur 60 5)
    bn_step "Latency / jitter / loss (${secs}s)"
    ser=$(probe_series "$ip" "$secs" 5)
    bn_kv p "$(series_summary "$ser")"
    bset ser "$ser"
    if [[ "$(bget p_recv 0)" -gt 0 ]]; then
        bset icmp_ok 1
        local nsamp wsz; nsamp=$(wc -w <<< "$ser"); wsz=$(( (nsamp + 29) / 30 )); (( wsz < 1 )) && wsz=1
        win=$(series_windows "$ser" "$wsz"); bset win "$win"
        bn_kv st "$(series_stats "$ser")"
        echo -e "avg $(bget p_avg) ms   loss $(bget p_loss)%   jitter $(bget p_jitter) ms"
    else bset icmp_ok 0; echo -e "${Y}no ICMP replies (filtered?)${NC}"; fi
    (( BN_ABORT )) && { bench_aborted; return 130; }

    # 2) TCP handshake to the destination port
    bn_step "TCP handshake to ${dport}"
    bn_kv t "$(probe_tcp "$ip" "$dport" 10)"
    [[ "$(bget t_ok 0)" -gt 0 ]] && bn_kv ci "$(probe_conn_info "$ip" "$dport")"      # nothing to look at when no handshake succeeded (and no minutes lost on a dropped SYN)
    if [[ "$(bget t_ok 0)" -gt 0 ]]; then echo -e "avg $(bget t_avg) ms   $(bget t_ok)/$(bget t_n) ok"
    else echo -e "${Y}port does not accept TCP${NC}"; fi
    (( BN_ABORT )) && { bench_aborted; return 130; }

    # 3) path MTU (against the MTU the kernel really uses towards this destination: a pin of the assistant counts)
    bn_step "Path MTU"
    if [[ "$(bget icmp_ok 0)" == 1 ]]; then
        imtu=$(bget r_effmtu 0); [[ "$imtu" =~ ^[0-9]+$ ]] && (( imtu >= 576 )) || imtu=1500
        bn_kv m "$(probe_mtu "$ip" "$imtu")"
        echo -e "path $(bget m_pmtu "?") / interface $(bget m_iface "?")   black-hole: $([[ "$(bget m_blackhole 0)" == 1 ]] && echo YES || echo no)"
    else bset m_icmp blocked; echo -e "${GR}skipped (ICMP filtered)${NC}"; fi
    (( BN_ABORT )) && { bench_aborted; return 130; }

    # 4) route
    bn_step "Route (MTR)"
    local mt=""
    if command -v mtr > /dev/null 2>&1; then
        if [[ "$(bget icmp_ok 0)" == 1 ]]; then mt=$(probe_mtr "$ip" 10); else mt=$(probe_mtr "$ip" 10 "$dport"); fi
        bset mtr_tool mtr
    else mt=$(probe_trace "$ip"); bset mtr_tool tracepath; fi
    bset mtr "$mt"
    if [[ -n "$mt" ]]; then echo -e "$(wc -l <<< "$mt") hop(s)"; else echo -e "${GR}no data${NC}"; fi
    (( BN_ABORT )) && { bench_aborted; return 130; }

    # 5) what flows through the tunnel right now
    bn_step "Live traffic (4s)"
    bn_kv lv "$(live_rate "$port" 4)"; bset conns "$(conn_count "$port")"
    echo -e "down $(bget lv_down 0) Mbit/s   up $(bget lv_up 0) Mbit/s   $(bget conns 0) conn"
    (( BN_ABORT )) && { bench_aborted; return 130; }

    # 6) throughput (full mode)
    if [[ "$mode" == full ]]; then
        if (( pport > 0 )) && { [[ "$(bget conns 0)" -gt 0 ]] || fl "$(bget lv_down 0)" '>' 1 || fl "$(bget lv_up 0)" '>' 1; }; then
            echo -e "\n  ${Y}$(bget conns 0) connection(s) use this tunnel right now ($(bget lv_down 0) down / $(bget lv_up 0) up Mbit/s).${NC}"
            echo -e "  ${GR}The speed test fills the line for about 40 seconds (up to ~4 GB of traffic at 1 Gbit/s) and slows them down.${NC}"
            confirm "Run the speed test now?" y || { pport=0; bset peer 0; }
            echo ""
        fi
        if (( pport > 0 )); then
            bn_step "Speed test (iperf3, ~60s)"
            echo ""
            bench_speed "$ip" "$pport"
            if [[ -n "$(bget dl4_mbps)" ]]; then echo -e "         down $(bget dl4_mbps) Mbit/s   up $(bget ul4_mbps "-") Mbit/s"
            else echo -e "         ${Y}the speed test did not produce a result${NC}"; fi
        elif (( inet )); then
            bn_step "Server -> Internet baseline"
            bn_kv inet "$(probe_inet_speed)"
            if [[ -n "$(bget inet_down)" ]]; then echo -e "down $(bget inet_down) Mbit/s   up $(bget inet_up) Mbit/s"
            else echo -e "${GR}unreachable${NC}"; fi
        else
            bn_step "Speed test"; echo -e "${GR}skipped (needs the helper on the destination)${NC}"
        fi
    fi
    trap - INT TERM HUP
    (( BN_ABORT )) && { bench_aborted; return 130; }
    bset secs "$(( $(date +%s) - t_start ))"
    bench_analyze
    return 0
}
bench_aborted() { trap - INT TERM HUP; bench_engine_stop; echo -e "\n  ${Y}Test cancelled.${NC}"; }

# ── scoring ──
sc_latency() { awk -v v="$1" 'BEGIN { print (v <= 40 ? 100 : v <= 80 ? 90 : v <= 150 ? 75 : v <= 250 ? 55 : 35) }'; }
sc_jitter()  { awk -v v="$1" 'BEGIN { print (v <= 2 ? 100 : v <= 5 ? 92 : v <= 10 ? 80 : v <= 20 ? 62 : v <= 40 ? 40 : 20) }'; }
sc_loss()    { awk -v v="$1" 'BEGIN { print (v <= 0 ? 100 : v <= 0.2 ? 90 : v <= 0.5 ? 80 : v <= 1 ? 65 : v <= 2 ? 45 : v <= 5 ? 25 : 5) }'; }
sc_bloat()   { awk -v v="$1" 'BEGIN { print (v <= 20 ? 100 : v <= 50 ? 85 : v <= 100 ? 65 : v <= 200 ? 40 : 15) }'; }
sc_tput()    { awk -v v="$1" 'BEGIN { print (v >= 500 ? 100 : v >= 200 ? 90 : v >= 100 ? 80 : v >= 50 ? 65 : v >= 25 ? 50 : v >= 10 ? 35 : 15) }'; }
rate_dot() {
    local s="$1"
    if   fl "$s" '>=' 90; then echo -e "${G}● EXCELLENT${NC}"
    elif fl "$s" '>=' 75; then echo -e "${G}● GOOD${NC}"
    elif fl "$s" '>=' 55; then echo -e "${Y}● FAIR${NC}"
    elif fl "$s" '>=' 35; then echo -e "${R}● POOR${NC}"
    else echo -e "${R}● BAD${NC}"; fi
}
grade_of() { awk -v s="$1" 'BEGIN { print (s >= 90 ? "A" : s >= 80 ? "B" : s >= 65 ? "C" : s >= 50 ? "D" : "F") }'; }
verdict_word() { case "$1" in 2) echo -e "${G}GREAT${NC}" ;; 1) echo -e "${Y}OK${NC}" ;; -1) echo -e "${GR}n/a${NC}" ;; *) echo -e "${R}POOR${NC}" ;; esac; }

# ── analysis: findings in plain words, each with the Optimization Assistant action that addresses it ──
bench_analyze() {
    BN_FIND=(); BN_RECO=()
    local method icmp rtt jit loss lost=0 sent=0 lsig=0 lsrc=icmp unit bloat dl1 dl4 cc prof dev kind tcp_ok tcp_n up blocked
    method=$(bget method); icmp=$(bget icmp_ok 0); cc=$(bget cc); prof=$(bget profile); dev=$(bget r_dev); kind=$(bget r_kind)
    tcp_ok=$(bget t_ok 0); tcp_n=$(bget t_n 0); up=$(bget up 1); blocked=$(bget blocked 0)
    # loss: HOW MANY probes were lost decides how serious it is (one lost ping of 40 is 2.5% and still means nothing)
    if [[ "$icmp" == 1 ]]; then
        rtt=$(bget p_avg); jit=$(bget p_jitter); loss=$(bget p_loss); sent=$(bget p_sent 0); lost=$(( sent - $(bget p_recv 0) ))
        if (( lost >= 3 )) || (( $(bget p_lossev 0) >= 2 )); then lsig=1; fi
    else
        rtt=$(bget ci_krtt "$(bget t_avg)"); jit=$(bget t_jitter); loss=""; lsrc=tcp
        if (( tcp_ok > 0 && tcp_n > 0 )); then               # no ICMP: failed handshakes are the only loss signal
            sent=$tcp_n; lost=$(( tcp_n - tcp_ok )); loss=$(awk -v n="$tcp_n" -v k="$tcp_ok" 'BEGIN { printf "%.1f", (n - k) * 100 / n }')
            (( lost >= 3 )) && lsig=1
        fi
    fi
    unit="probes"; [[ "$lsrc" == tcp ]] && unit="TCP connection attempts"
    bset l_cnt "$lost"; bset l_sent "$sent"; bset l_sig "$lsig"; bset l_src "$lsrc"
    if [[ -n "$loss" ]]; then
        if (( lsig )); then bset l_eff "$loss"; else bset l_eff "$(awk -v l="$loss" 'BEGIN { print (l > 0.5 ? 0.5 : l) }')"; fi
    fi

    # is the tunnel itself in order?
    if [[ "$blocked" == 1 ]]; then bn_find crit "This tunnel is BLOCKED in PFM: nobody can connect through it. (The test below only measures the leg from this server to the destination.)"
    elif [[ "$up" == 0 ]]; then
        bn_find crit "The tunnel is not running: $([[ "$method" == iptables ]] && echo "its NAT rule is missing" || echo "$method is not listening on :$(bget port)"). Run: pfm restore, then pfm doctor $(bget port). (The test below only measures the leg from this server to the destination.)"
    fi
    # reachability
    if [[ "$icmp" != 1 && "$tcp_ok" == 0 ]]; then
        bset nomeasure 1
        bn_find crit "Nothing answered - neither ICMP nor TCP port $(bget dport). The destination is down, the IP/port is wrong or a firewall blocks this server. If it only carries UDP (WireGuard, QUIC, games), the Bench Test cannot probe it from here."
    elif [[ "$tcp_ok" == 0 ]]; then
        bn_find warn "TCP port $(bget dport) does not accept connections. Normal for UDP-only services (WireGuard, QUIC, games); otherwise the service is down or filtered."
    elif [[ "$icmp" != 1 ]]; then
        bn_find info "ICMP is filtered on the way, so loss / MTU numbers rely on TCP only and are less precise."
    fi

    # loss
    if [[ -n "$loss" ]]; then
        if (( lsig )) && fl "$loss" '>=' 2; then
            bn_find crit "Packet loss ${loss}% towards the destination ($lost of $sent $unit). TCP speed collapses with loss; games and calls break up. Check the route below to see where it starts."
            [[ "$cc" != bbr && "$method" != iptables ]] && bn_reco bbr "BBR keeps TCP fast on lossy paths (cubic backs off hard)"
        elif (( lsig )) && fl "$loss" '>=' 0.5; then
            bn_find warn "Packet loss ${loss}% ($lost of $sent $unit) - noticeable for gaming/calls and it lowers single-download speed."
            [[ "$cc" != bbr && "$method" != iptables ]] && bn_reco bbr "BBR tolerates loss much better than cubic"
        elif (( lost > 0 )); then
            bn_find info "$lost of $sent $unit got no answer (${loss}%). That is too few to call it a pattern - a rate-limited ping or a single drop looks the same. The Full test (60 s) settles it."
        else bn_find ok "No packet loss ($sent $unit answered)."; fi
        if [[ "$icmp" == 1 ]] && (( lsig )) && (( tcp_n >= 5 && tcp_ok == tcp_n )); then
            bn_find info "All $tcp_n TCP connections to port $(bget dport) succeeded, so part of the ICMP loss may be the destination rate-limiting ping rather than real packet loss."
        fi
        if (( lsig )) && fl "$(bget p_maxburst 0)" '>=' 5; then
            bn_find warn "Loss comes in bursts (up to $(bget p_maxburst) packets in a row): a link flap or a congested hop, not random noise."
        fi
    fi
    # jitter / spikes
    if [[ -n "$jit" ]]; then
        if fl "$jit" '>=' 30; then
            bn_find crit "Jitter ${jit} ms: very unstable latency - gaming and voice/video calls will stutter."
            [[ "$prof" != gaming && "$method" != iptables ]] && bn_reco profile:gaming "stabilise latency for this tunnel"
        elif fl "$jit" '>=' 10; then
            bn_find warn "Jitter ${jit} ms: fine for browsing/streaming, noticeable in gaming."
            [[ "$prof" != gaming && "$method" != iptables ]] && bn_reco profile:gaming "lower jitter for this tunnel"
        fi
    fi
    local sp; sp=$(bget st_spikes 0)
    if fl "$sp" '>=' 4; then bn_find warn "$sp latency spike$( ((sp == 1)) || echo s) during the test (a few times higher than normal): bursts of congestion on the path."; fi
    if [[ -n "$rtt" ]] && fl "$rtt" '>=' 250; then bn_find info "Latency ${rtt} ms is high - the path is long or indirect. Check the route for a detour."; fi

    # MTU (compared with what the kernel really uses towards this destination)
    local pm im bh pinned dm
    pm=$(bget m_pmtu); im=$(bget m_iface); bh=$(bget m_blackhole 0); pinned=$(bget r_pinned 0); dm=$(bget r_devmtu)
    if [[ "$(bget m_unreliable 0)" == 1 ]]; then
        bn_find info "The MTU measurement was not reliable (replies were lost or rate-limited), so it is ignored."
        BN[m_pmtu]=""; BN[m_blackhole]=0; pm=""; bh=0
    fi
    if [[ "$bh" == 1 ]]; then
        bn_find crit "MTU black hole: packets over ${pm} bytes vanish and the network never says so. Big TCP transfers stall while pings and small requests work."
        bn_reco mtu "find and apply the MTU that really crosses this path"
        [[ "$method" == iptables ]] && bn_reco mss "clamp TCP MSS so no packet is too big"
    elif [[ "$pm" =~ ^[0-9]+$ && "$im" =~ ^[0-9]+$ ]] && (( pm < im )); then
        bn_find warn "Path MTU is ${pm} but ${dev} uses ${im}: oversize packets get fragmented or need an extra round trip."
        bn_reco mtu "match the interface MTU to the ${pm}-byte path"
        [[ "$method" == iptables ]] && bn_reco mss "clamp TCP MSS to the path MTU"
    elif [[ "$pm" =~ ^[0-9]+$ ]]; then
        if [[ "$pinned" == 1 ]]; then bn_find ok "MTU is consistent (path ${pm} = the MTU pinned on the route; ${dev} itself allows ${dm}). The pin limits the probes, so a better path would not show here - MTU auto-tune re-checks without it."
        else bn_find ok "MTU is consistent (path ${pm} = interface ${im})."; fi
    fi
    if [[ "$kind" =~ ^(gre|gretap|ipip|sit|wireguard|vxlan|ip6gre|ip6gretap|ip6tnl|geneve)$ && "$method" == iptables && ! "$bh" == 1 ]]; then
        bn_reco mss "tunnel device ($kind) + kernel NAT: clamp the TCP MSS"
    fi

    # speed suite
    dl1=$(bget dl1_mbps); dl4=$(bget dl4_mbps)
    if (( $(bget peer 0) > 0 )) && [[ -z "$dl4" ]]; then
        bn_find warn "The speed test could not run ($(bget dl4_err "no result from iperf3")). Check that the helper still runs on the destination and that TCP and UDP port $(bget peer) are open to this server."
    fi
    if [[ -n "$dl4" ]]; then
        # latency under load: only pings that really came back count; the tail is compared with the idle tail (jitter cancels out)
        local bl_dl="" bl_ul="" ld lu
        ld=$(bget ldl_recv 0); lu=$(bget lul_recv 0)
        (( ld > 0 )) && bl_dl=$(awk -v l="$(bget ldl_p95 0)" -v i="$(bget p_p95 "${rtt:-0}")" 'BEGIN { d = l - i; print d < 0 ? 0 : d }')
        (( lu > 0 )) && bl_ul=$(awk -v l="$(bget lul_p95 0)" -v i="$(bget p_p95 "${rtt:-0}")" 'BEGIN { d = l - i; print d < 0 ? 0 : d }')
        bset bl_dl "$bl_dl"; bset bl_ul "$bl_ul"
        if [[ "$icmp" == 1 ]] && { (( ld == 0 )) || (( lu == 0 )); } && (( $(bget ldl_sent 0) + $(bget lul_sent 0) > 0 )); then
            bset load_lost 1
            bn_find crit "No ping got through while the line was busy ($( (( ld == 0 )) && echo download )$( (( ld == 0 && lu == 0 )) && echo " and ")$( (( lu == 0 )) && echo upload )): the connection is saturated so badly that everything else stops - or the destination rate-limits ping under load."
            [[ "$cc" != bbr && "$method" != iptables ]] && bn_reco bbr "BBR + fq keep queues short while the line is busy"
        fi
        if [[ -n "$bl_dl$bl_ul" ]]; then
            bloat=$(awk -v a="${bl_dl:-0}" -v b="${bl_ul:-0}" 'BEGIN { print (a > b ? a : b) }'); bset bloat "$bloat"
            if fl "$bloat" '>=' 300; then
                bn_find crit "Bufferbloat: latency jumps by +$(fmt0 "$bloat") ms while the line is busy. During any big download everything else lags."
            elif fl "$bloat" '>=' 100; then bn_find warn "Latency rises by +$(fmt0 "$bloat") ms under load (bufferbloat)."
            elif fl "$bloat" '>=' 30; then bn_find info "Latency rises by +$(fmt0 "$bloat") ms under load - acceptable."
            else bn_find ok "Latency stays flat under load (+$(bn_ms "$bloat") ms)."; fi
            if fl "$bloat" '>=' 100; then
                [[ "$cc" != bbr && "$method" != iptables ]] && bn_reco bbr "BBR + fq keep queues short while the line is busy"
                [[ "$prof" != gaming && "$method" != iptables ]] && bn_reco profile:gaming "short queues and quick ACKs for latency-sensitive use"
            fi
        fi
        if [[ -n "$dl1" ]] && fl "$dl4" '>' 20 && fl "${rtt:-0}" '>=' 5 && fl "$dl1" '<' "$(awk -v v="$dl4" 'BEGIN { print v * 0.35 }')"; then
            if [[ "$method" == iptables ]]; then
                bn_find info "One connection reaches only $(bn_mbps "$dl1") while 4 together reach $(bn_mbps "$dl4"): a single TCP stream is limited on this path (latency / loss). With kernel NAT the window is set by the user's device and the destination, not by this server - nothing to tune here."
            else
                bn_find warn "One connection reaches only $(bn_mbps "$dl1") while 4 together reach $(bn_mbps "$dl4"): single downloads are held back by loss or too-small TCP windows."
                bn_reco buffers "bigger TCP windows for the latency of this path"
                [[ "$cc" != bbr ]] && bn_reco bbr "BBR fills the pipe with a single connection"
            fi
        fi
        local ratio dbest ecpu engflag=0; dbest=$(awk -v a="$dl4" -v b="$(bget dl4b_mbps 0)" 'BEGIN { print (b + 0 > a + 0 ? b : a) }')
        ratio=$(awk -v e="$(bget eng_mbps 0)" -v d="$dbest" 'BEGIN { print (d > 0 ? e * 100 / d : 0) }')
        bset eng_ratio "$ratio"; ecpu=$(bget eng_cpu 0)
        if [[ -n "$(bget eng_mbps)" ]]; then
            if fl "$ratio" '<' 75; then
                if fl "$ecpu" '>=' 80 || fl "$(bget engc_max 0)" '>=' 90; then
                    engflag=1
                    bn_find warn "The $method engine delivers only $(fmt0 "$ratio")% of the direct speed and its CPU is saturated (${ecpu}% of a core): the forwarder itself is the bottleneck."
                    bn_reco engine "try the other engine (iptables: no userspace copy)"
                else
                    bn_find info "The $method engine reached only $(fmt0 "$ratio")% of the direct speed in this run, but its CPU was not saturated (${ecpu}%), so this is probably the variation of the internet path. Run the test again before drawing conclusions."
                fi
            elif fl "$ratio" '<' 90; then bn_find info "The $method engine costs some speed ($(fmt0 "$ratio")% of the direct speed gets through)."
            else bn_find ok "The $method engine adds almost nothing ($(fmt0 "$ratio")% of direct speed)."; fi
        fi
        local sirq cmax; sirq=$(bget cpu_softirq 0); cmax=$(bget cpu_max 0)
        if fl "$cmax" '>=' 90 && fl "$sirq" '>=' 40; then
            bn_find warn "Packet processing saturates one CPU core ($(bget cpu_maxcpu): ${cmax}% busy, ${sirq}% of it in network interrupts): the server, not the link, limits the speed."
            bn_reco nic "spread packets over all cores (RPS), check offloads"
        elif (( engflag )); then :                               # the engine finding above already explains the busy core
        elif [[ -n "$(bget eng_cpu)" ]] && fl "$ecpu" '>=' 90; then
            bn_find warn "The $method process alone uses ${ecpu}% of a CPU core: a single-threaded forwarder is the limit, more link speed will not help."
            bn_reco engine "try the other engine (iptables: no userspace copy)"
        elif fl "$cmax" '>=' 90; then
            bn_find info "One CPU core ($(bget cpu_maxcpu)) was fully busy during the speed test. That can be the speed-test client itself (iperf3 older than 3.16 uses one thread), so it is no proof that forwarding is the limit."
        fi
        local rpct; rpct=$(awk -v r="$(bget dl4_retr 0)" -v m="$dl4" -v s="$(bget spd_secs 8)" 'BEGIN { segs = m * 1e6 / 8 * s / 1448; printf "%.2f", (segs > 0 ? r * 100 / segs : 0) }')
        if fl "$rpct" '>=' 1; then
            bn_find warn "$(bget dl4_retr) TCP retransmissions in the download test (${rpct}% of the segments): packets are being dropped on the path or in a full queue."
        fi
        if [[ -n "$(bget udp_loss)" ]]; then
            if fl "$(bget udp_loss)" '>=' 0.5 || fl "$(bget udp_jitter 0)" '>=' 8; then
                bn_find warn "Game-like UDP stream: loss $(bget udp_loss)%, jitter $(bget udp_jitter) ms."
                [[ "$prof" != gaming && "$method" != iptables ]] && bn_reco profile:gaming "tune the tunnel for UDP/latency use"
            else bn_find ok "UDP stream is clean (loss $(bget udp_loss)%, jitter $(bget udp_jitter) ms)."; fi
        fi
        local nd; nd=$(( $(bget nic_drops 0) + $(bget softnet_drops 0) ))
        if (( nd >= 100 )); then
            bn_find warn "The server dropped $nd packets itself during the test (NIC $(bget nic_drops), backlog $(bget softnet_drops)): its receive queues are too small or one core is overloaded."
            bn_reco nic "bigger ring/backlog and RPS"
        elif (( nd > 0 )); then bn_find info "The server's own queues dropped $nd packet(s) during the test - harmless at this level."; fi
        if fl "$(bget softnet_squeeze 0)" '>=' 100; then bn_reco nic "CPU ran out of packet-processing budget during the test"; fi
    fi

    # host
    local ctp=0
    [[ "$(bget ct_max)" =~ ^[0-9]+$ && "$(bget ct_count)" =~ ^[0-9]+$ && "$(bget ct_max)" -gt 0 ]] && ctp=$(( $(bget ct_count) * 100 / $(bget ct_max) ))
    bset ct_pct "$ctp"
    if (( ctp >= 70 )); then bn_find warn "Connection tracking is ${ctp}% full: new connections will be dropped when it reaches 100%."; bn_reco conntrack "raise the connection-tracking limit"; fi
    if fl "$(bget load 0)" '>' "$(bget cpus 1)"; then bn_find warn "Server load ($(bget load)) is above its CPU count ($(bget cpus)): the machine itself is busy."; fi
    if [[ "$method" != iptables && "$cc" != bbr ]]; then
        [[ "$(sys_get net.ipv4.tcp_available_congestion_control)" == *bbr* || -e /sys/module/tcp_bbr ]] && bn_reco bbr "this engine terminates TCP here: BBR beats ${cc:-cubic} on long or lossy paths"
    fi
    if [[ "$method" == iptables && "$cc" != bbr ]]; then bn_find info "Congestion control is ${cc:-?}; it does not affect iptables-forwarded connections (the kernel only NATs them)."; fi
    local need
    need=$(awk -v r="${rtt:-100}" -v m="${dl4:-1000}" 'BEGIN { if (m < 100) m = 100; printf "%.0f", 2 * m * 1e6 / 8 * r / 1000 }')
    if [[ "$method" != iptables && "$(bget rmem_max)" =~ ^[0-9]+$ ]] && (( $(bget rmem_max) * 5 < need * 4 )) && fl "${rtt:-0}" '>=' 60; then      # a real shortfall (>25%), not a rounding difference
        bn_find info "TCP receive window limit ($(awk -v v="$(bget rmem_max)" 'BEGIN { printf "%.1f", v / 1048576 }') MB) is below what this latency needs ($(awk -v v="$need" 'BEGIN { printf "%.1f", v / 1048576 }') MB) for full speed."
        bn_reco buffers "raise TCP buffers to cover latency x bandwidth"
    fi
    bench_score
}

bench_score() {
    local w=0 t=0 s rtt jit loss
    if [[ "$(bget icmp_ok 0)" == 1 ]]; then rtt=$(bget p_avg); jit=$(bget p_jitter)
    else rtt=$(bget ci_krtt "$(bget t_avg)"); jit=$(bget t_jitter); fi
    loss=$(bget l_eff)                     # the loss figure the findings use: ONE lost probe is damped to 0.5%, three or more count in full
    if [[ "$(bget nomeasure 0)" == 1 ]]; then      # nothing answers: there is nothing to grade (not "0 out of 100": it may simply be a UDP-only service)
        bset score ""; bset grade "-"; bset v_game -1; bset v_stream -1; bset v_daily -1; bset v_calls -1; return
    fi
    add() { t=$(awk -v t="$t" -v s="$1" -v w="$2" 'BEGIN { print t + s * w }'); w=$((w + $2)); }
    [[ -n "$rtt" ]] && { s=$(sc_latency "$rtt"); bset sc_lat "$s"; add "$s" 20; }
    [[ -n "$jit" ]] && { s=$(sc_jitter "$jit"); bset sc_jit "$s"; add "$s" 20; }
    [[ -n "$loss" ]] && { s=$(sc_loss "$loss"); bset sc_loss "$s"; add "$s" 25; }
    local pm im; pm=$(bget m_pmtu); im=$(bget m_iface)
    if [[ "$(bget m_blackhole 0)" == 1 ]]; then bset sc_mtu 20; add 20 10
    elif [[ "$pm" =~ ^[0-9]+$ && "$im" =~ ^[0-9]+$ ]]; then (( pm < im )) && s=75 || s=100; bset sc_mtu "$s"; add "$s" 10; fi
    if [[ "$(bget load_lost 0)" == 1 ]]; then bset sc_bloat 15; add 15 15           # nothing got through under load: the worst answer, not a missing one
    elif [[ -n "$(bget bloat)" ]]; then s=$(sc_bloat "$(bget bloat)"); bset sc_bloat "$s"; add "$s" 15; fi
    [[ -n "$(bget dl4_mbps)" ]] && { s=$(sc_tput "$(bget dl4_mbps)"); bset sc_tput "$s"; add "$s" 10; }
    unset -f add
    (( w > 0 )) && bset score "$(awk -v t="$t" -v w="$w" 'BEGIN { printf "%.0f", t / w }')" || bset score 0
    # a chain is as strong as its weakest link: a serious problem caps the grade however good the rest is
    local cap=100 capr="" bl; bl=$(bget bloat)
    capf() { fl "$cap" '>' "$1" && { cap=$1; capr="$2"; }; return 0; }
    if [[ -n "$loss" && "$(bget l_sig 0)" == 1 ]]; then      # a handful of lost probes is not a reason to cap anything
        fl "$loss" '>=' 1 && capf 78 "packet loss"; fl "$loss" '>=' 2 && capf 60 "packet loss"; fl "$loss" '>=' 5 && capf 40 "packet loss"
    fi
    [[ -n "$jit" ]] && { fl "$jit" '>=' 20 && capf 75 jitter; fl "$jit" '>=' 30 && capf 65 jitter; fl "$jit" '>=' 40 && capf 55 jitter; }
    [[ -n "$bl" ]] && { fl "$bl" '>=' 100 && capf 80 bufferbloat; fl "$bl" '>=' 300 && capf 65 bufferbloat; }
    [[ "$(bget load_lost 0)" == 1 ]] && capf 65 "no reply under load"
    [[ "$(bget m_blackhole 0)" == 1 ]] && capf 50 "MTU black hole"
    [[ "$(bget blocked 0)" == 1 || "$(bget up 1)" == 0 ]] && capf 40 "tunnel not running"
    unset -f capf
    if fl "$(bget score)" '>' "$cap"; then bset score_raw "$(bget score)"; bset score "$cap"; bset score_cap "$capr"; fi
    bset grade "$(grade_of "$(bget score)")"
    # what the tunnel is good for (-1 = cannot be judged from what was measured)
    local l="${rtt:-999}" j="${jit:-99}" ls="${loss:-0}" b="${BN[bloat]:-0}" g=0 st=0 dy=0 ca=0
    [[ "$(bget load_lost 0)" == 1 ]] && b=999
    if   fl "$l" '<=' 70 && fl "$j" '<=' 8 && fl "$ls" '<=' 0.3 && fl "$b" '<=' 40; then g=2
    elif fl "$l" '<=' 120 && fl "$j" '<=' 15 && fl "$ls" '<=' 1 && fl "$b" '<=' 100; then g=1; fi
    local d4; d4=$(bget dl4_mbps)
    if [[ -z "$d4" ]]; then st=-1                                   # streaming / downloads depend on the speed: the quick test never measures it
    elif fl "$ls" '<=' 0.5 && fl "$d4" '>=' 50; then st=2
    elif fl "$ls" '<=' 2 && fl "$d4" '>=' 15; then st=1; fi
    if   fl "$ls" '<=' 2 && fl "$l" '<=' 250; then dy=2; elif fl "$ls" '<=' 5; then dy=1; fi
    if   fl "$j" '<=' 15 && fl "$ls" '<=' 1; then ca=2; elif fl "$j" '<=' 30 && fl "$ls" '<=' 3; then ca=1; fi
    bset v_game "$g"; bset v_stream "$st"; bset v_daily "$dy"; bset v_calls "$ca"
}

# ── report ──
bn_wrap() {    # bn_wrap <coloured marker> <text>: text folded to the report width, continuation lines indented
    local mark="$1" first=1 line
    while IFS= read -r line; do
        if (( first )); then printf "   %b %s\n" "$mark" "$line"; first=0; else printf "     %s\n" "$line"; fi
    done < <(fold -s -w 70 <<< "$2" | sed 's/ *$//')
}
bn_mbps() {
    if [[ -z "$1" ]]; then printf '%s' '-'
    elif fl "$1" '>=' 1000; then printf '%s Gbit/s' "$(awk -v v="$1" 'BEGIN { printf "%.2f", v / 1000 }')"
    else printf '%s Mbit/s' "$(fmt1 "$1")"; fi
}
bn_row() { printf "   ${W}%-12s${NC} %-50s %b\n" "$1" "$2" "$3"; }
bn_ms() { awk -v v="${1:-0}" 'BEGIN { if (v + 0 >= 10) printf "%.0f", v; else printf "%.1f", v }'; }       # milliseconds: no decimals above 10, one below (0.4 must not read as 0)
bench_report_summary() {
    local sc grade bar n filled method ip dport
    sc=$(bget score 0); grade=$(bget grade "?"); method=$(bget method); ip=$(bget dest); dport=$(bget dport)
    filled=$(( sc * 20 / 100 )); bar=""; for ((n = 0; n < 20; n++)); do (( n < filled )) && bar+="█" || bar+="░"; done
    local gc="$G"; fl "$sc" '<' 80 && gc="$Y"; fl "$sc" '<' 55 && gc="$R"
    echo -e "  ${B}${C}PFM BENCH TEST${NC}  ${GR}PFM v$(bget ver) · $(date -d "@$(bget ts)" '+%Y-%m-%d %H:%M' 2> /dev/null) · $(bget mode) · $(bget secs)s${NC}"
    echo -e "  ${GR}$(hr 76)${NC}"
    echo -e "  ${W}Tunnel${NC}  :$(bget port) → ${ip}:${dport}   engine ${method} · profile $(bget profile) · owner $(bget owner)"
    echo -e "  ${W}Server${NC}  $(bget host) · $(bget os) · $(bget cpus) vCPU / $(bget ram) MB · $(bget virt) · kernel $(bget kernel)"
    echo -e "  ${W}Path${NC}    $(bget r_dev) ($(bget r_kind), MTU $(bget r_devmtu)) · src $(bget r_src) · cc $(bget cc) · qdisc $(bget qdisc)"
    echo -e "  ${GR}$(hr 76)${NC}"
    if [[ "$(bget nomeasure 0)" == 1 ]]; then
        echo -e "  ${W}OVERALL${NC}  ${Y}NOT MEASURABLE${NC}  ${GR}nothing answered from this server (see findings)${NC}"
    else
        echo -e "  ${W}OVERALL${NC}  ${gc}${bar}${NC}  ${B}${sc}/100${NC}  Grade ${B}${gc}${grade}${NC}$([[ -n "$(bget score_cap)" ]] && echo "  ${GR}limited by $(bget score_cap)${NC}")"
        echo -e "  ${GR}covers the server → destination leg only$([[ -z "$(bget dl4_mbps)" ]] && echo " · quality only, no speed / load data")${NC}"
    fi
    echo -e "  ${GR}Use:${NC} Gaming $(verdict_word "$(bget v_game 0)") · Streaming/Download $(verdict_word "$(bget v_stream 0)") · Calls $(verdict_word "$(bget v_calls 0)") · Daily $(verdict_word "$(bget v_daily 0)")"
    echo -e "  ${GR}$(hr 76)${NC}"
    echo -e "  ${C}QUALITY${NC} ${GR}(this server → destination)${NC}"
    if [[ "$(bget icmp_ok 0)" == 1 ]]; then
        bn_row "Latency" "avg $(bget p_avg) ms (min $(bget p_min) / p95 $(bget p_p95) / max $(bget p_max))" "$(rate_dot "$(bget sc_lat 0)")"
        bn_row "Jitter" "$(bget p_jitter) ms avg change between packets" "$(rate_dot "$(bget sc_jit 0)")"
        bn_row "Packet loss" "$(bget p_loss)% ($(( $(bget p_sent 0) - $(bget p_recv 0) ))/$(bget p_sent 0) lost, longest gap $(bget p_maxburst 0))$([[ "$(bget l_sig 0)" != 1 && "$(bget l_cnt 0)" -gt 0 ]] && echo ' - isolated')" "$(rate_dot "$(bget sc_loss 0)")"
        local wn spk=""; wn=$(bget win); local nwin; nwin=$(wc -w <<< "$wn")
        if (( nwin > 1 )); then
            local slo shi
            slo=$(awk '{ m = 1e18; for (i = 1; i <= NF; i++) if ($i >= 0 && $i < m) m = $i; print (m == 1e18 ? 0 : m) }' <<< "$wn")
            shi=$(awk -v lo="$slo" '{ m = 0; for (i = 1; i <= NF; i++) if ($i > m) m = $i; t = lo * 1.5 + 2; print (m > t ? m : t) }' <<< "$wn")
            spk=$(spark "$wn" "$slo" "$shi"); spk="${spk//✗/${R}✗${NC}}"
            printf "   ${W}%-12s${NC} %b%*s ${GR}%s${NC}\n" "Stability" "$spk" $(( 40 - nwin > 1 ? 40 - nwin : 1 )) "" "$(bget st_spikes 0) spike$( (($(bget st_spikes 0) == 1)) || echo s)"
        fi
    else
        bn_row "Latency" "ICMP filtered" "${Y}● n/a${NC}"
    fi
    if [[ "$(bget t_ok 0)" -gt 0 ]]; then bn_row "TCP connect" "$(bget t_ok)/$(bget t_n) ok, handshake $(bget ci_krtt "$(bget t_avg)") ms, MSS $(bget ci_mss "?")" ""
    else bn_row "TCP connect" "port ${dport} did not accept TCP" "${Y}● n/a${NC}"; fi
    local mt
    if [[ "$(bget m_icmp)" == blocked ]]; then mt="not measured (ICMP filtered)"
    elif [[ "$(bget m_unreliable 0)" == 1 ]]; then mt="not reliable (replies lost / rate-limited) - ignored"
    elif [[ -n "$(bget m_pmtu)" ]]; then mt="path $(bget m_pmtu) / interface $(bget m_iface), TCP MSS $(( $(bget m_pmtu) - $(is_ipv6 "$(bget ip)" && echo 60 || echo 40) ))$([[ "$(bget r_pinned 0)" == 1 ]] && echo ', route pin')"
    else mt="-"; fi
    bn_row "MTU" "$mt" "$( [[ -n "$(bget sc_mtu)" ]] && rate_dot "$(bget sc_mtu)" )"
    if [[ -n "$(bget dl4_mbps)" || -n "$(bget inet_down)" || -n "$(bget lv_down)" ]]; then
        echo -e "  ${GR}$(hr 76)${NC}"
        echo -e "  ${C}$([[ -n "$(bget dl4_mbps)" || -n "$(bget inet_down)" ]] && echo THROUGHPUT || echo "LIVE TRAFFIC")${NC}"
        if [[ -n "$(bget dl4_mbps)" ]]; then
            bn_row "Download" "$(bn_mbps "$(bget dl4_mbps)") (4 streams)  ·  $(bn_mbps "$(bget dl1_mbps)") (1 stream)" "$(rate_dot "$(bget sc_tput 0)")"
            bn_row "Upload" "$(bn_mbps "$(bget ul4_mbps)") (4 streams)  ·  retransmits $(bget ul4_retr 0)" ""
            [[ -n "$(bget udp_loss)" ]] && bn_row "UDP 1 Mbit/s" "loss $(bget udp_loss)%  jitter $(bget udp_jitter) ms (200-byte packets)" ""
            if [[ "$(bget load_lost 0)" == 1 ]]; then bn_row "Under load" "no ping got through while the line was busy" "$(rate_dot "$(bget sc_bloat 0)")"
            elif [[ -n "$(bget bloat)" ]]; then bn_row "Under load" "+$(bn_ms "$(bget bloat 0)") ms (worst ping: idle $(bn_ms "$(bget p_p95 0)"), down $([[ -n "$(bget bl_dl)" ]] && bn_ms "$(bget ldl_p95 0)" || echo -), up $([[ -n "$(bget bl_ul)" ]] && bn_ms "$(bget lul_p95 0)" || echo -) ms)" "$(rate_dot "$(bget sc_bloat 0)")"
            else bn_row "Under load" "not measured (no ICMP answers)" "${Y}● n/a${NC}"; fi
            [[ -n "$(bget eng_mbps)" ]] && bn_row "Engine" "$(bget method) = $(fmt0 "$(bget eng_ratio 0)")% of direct speed, engine CPU $(bget eng_cpu 0)%, busiest core $(bget engc_max "-")%" ""
        elif [[ -n "$(bget inet_down)" ]]; then
            bn_row "Server→Net" "down $(bget inet_down) / up $(bget inet_up) Mbit/s (Cloudflare, not via tunnel)" ""
        fi
        bn_row "Live now" "down $(bget lv_down 0) / up $(bget lv_up 0) Mbit/s, $(bget conns 0) connections" ""
    else
        bn_row "Live now" "down $(bget lv_down 0) / up $(bget lv_up 0) Mbit/s, $(bget conns 0) connections" ""
    fi
    echo -e "  ${GR}$(hr 76)${NC}"
    echo -e "  ${C}FINDINGS${NC}"
    local f sev txt shown=0 mk want
    for want in crit warn info ok; do          # the page has room for 7 lines: the serious ones must never be the ones cut
        for f in "${BN_FIND[@]}"; do
            sev="${f%%|*}"; txt="${f#*|}"; [[ "$sev" == "$want" ]] || continue
            (( shown >= 7 )) && continue
            case "$sev" in crit) mk="${R}✗${NC}" ;; warn) mk="${Y}!${NC}" ;; info) mk="${GR}i${NC}" ;; *) mk="${G}✓${NC}" ;; esac
            bn_wrap "$mk" "$txt"
            shown=$((shown + 1))
        done
    done
    (( ${#BN_FIND[@]} > 7 )) && echo -e "   ${GR}... and $(( ${#BN_FIND[@]} - 7 )) more finding(s) of lower importance on the details page (d)${NC}"
    [[ ${#BN_FIND[@]} -eq 0 ]] && echo -e "   ${G}✓${NC} Nothing to worry about."
    if [[ ${#BN_RECO[@]} -gt 0 ]]; then
        echo -e "  ${GR}$(hr 76)${NC}"
        echo -e "  ${C}NEXT STEPS${NC} ${GR}(Optimization Assistant: PFM → 10)${NC}"
        local i=0 r id why wl wfirst
        for r in "${BN_RECO[@]}"; do
            i=$((i + 1)); id="${r%%|*}"; why="${r#*|}"; wfirst=1
            while IFS= read -r wl; do           # long reasons are folded under the label so the page stays screenshot-wide
                if (( wfirst )); then printf "   ${W}%d)${NC} %-26s ${GR}%s${NC}\n" "$i" "$(assist_label "$id")" "$wl"; wfirst=0
                else printf "%34s${GR}%s${NC}\n" "" "$wl"; fi
            done < <(fold -s -w 54 <<< "$why" | sed 's/ *$//')
        done
        echo -e "  ${GR}After applying, run this test again - the report shows what changed.${NC}"
    fi
}
bench_report_details() {
    echo -e "  ${B}${C}PFM BENCH TEST - details${NC}  ${GR}:$(bget port) → $(bget dest):$(bget dport)${NC}"
    echo -e "  ${GR}$(hr 76)${NC}"
    if [[ "$(bget mtr_tool)" == tracepath ]]; then echo -e "  ${C}ROUTE${NC} ${GR}(tracepath - mtr is not installed: one probe per hop, so no loss figures)${NC}"
    else echo -e "  ${C}ROUTE${NC} ${GR}(MTR from this server, 10 probes per hop)${NC}"; fi
    if [[ -n "$(bget mtr)" ]]; then
        printf "   ${GR}%-4s %-34s %6s %8s %8s %8s %7s${NC}\n" "hop" "host" "loss%" "avg ms" "best" "worst" "stdev"
        local h hh lo av be wo sd lc
        while IFS='|' read -r h hh lo _ _ av be wo sd; do
            [[ -n "$h" ]] || continue
            lc="$G"; if [[ "$lo" =~ ^[0-9.]+$ ]]; then fl "$lo" '>' 0 && lc="$Y"; fl "$lo" '>=' 20 && lc="$R"; else lc="$GR"; fi
            printf "   %-4s %-34s ${lc}%6s${NC} %8s %8s %8s %7s\n" "$h" "$hh" "$lo" "$av" "$be" "$wo" "$sd"
        done <<< "$(bget mtr)"
        [[ "$(bget mtr_tool)" == tracepath ]] || echo -e "   ${GR}Loss on middle hops only (not at the last hop) is ICMP rate-limiting.${NC}"
    else echo -e "   ${GR}no route data${NC}"; fi
    echo -e "  ${GR}$(hr 76)${NC}"
    echo -e "  ${C}RAW NUMBERS${NC}"
    echo -e "   ICMP   sent $(bget p_sent 0) recv $(bget p_recv 0) · min $(bget p_min -) avg $(bget p_avg -) p50 $(bget p_p50 -) p95 $(bget p_p95 -) max $(bget p_max -) ms · stdev $(bget p_stdev -) · loss events $(bget p_lossev 0)"
    echo -e "   TCP    $(bget t_ok 0)/$(bget t_n 0) ok · min $(bget t_min -) avg $(bget t_avg -) max $(bget t_max -) ms · kernel: mss $(bget ci_mss -) pmtu $(bget ci_pmtu -) rtt $(bget ci_krtt -) ms cwnd $(bget ci_cwnd -) cc $(bget ci_cc -)"
    echo -e "   MTU    interface $(bget m_iface -) · path $(bget m_pmtu -) · router frag-needed message: $([[ "$(bget m_fragmsg 0)" == 1 ]] && echo yes || echo no) · tunnel overhead $(bget r_overhead 0) B"
    echo -e "   Route  dev $(bget r_dev) ($(bget r_kind)) via $(bget r_via -) · tunnel remote $(bget r_remote -) local $(bget r_local -)"
    if [[ -n "$(bget dl4_mbps)" ]]; then
        echo -e "   iperf3 down1 $(bget dl1_mbps -) · down4 $(bget dl4_mbps -) (retr $(bget dl4_retr 0)) · up4 $(bget ul4_mbps -) (retr $(bget ul4_retr 0)) Mbit/s"
        echo -e "   Host   CPU during download: all $(bget cpu_all -)% · busiest $(bget cpu_max -)% ($(bget cpu_maxcpu -)) · softirq $(bget cpu_softirq -)% · TCP retrans $(bget tcp_retrans_pct -)%"
        echo -e "   Drops  NIC $(bget nic_drops 0) · backlog $(bget softnet_drops 0) · budget squeeze $(bget softnet_squeeze 0)"
    fi
    echo -e "   Host   load $(bget load) on $(bget cpus) CPU · conntrack $(bget ct_count -)/$(bget ct_max -) (${BN[ct_pct]:-0}%) · TCP rmem max $(( ${BN[rmem_max]:-0} / 1048576 )) MB"
    if (( ${#BN_FIND[@]} > 7 )); then
        echo -e "  ${GR}$(hr 76)${NC}"; echo -e "  ${C}ALL FINDINGS${NC}"
        local f sev txt mk want
        for want in crit warn info ok; do
            for f in "${BN_FIND[@]}"; do
                sev="${f%%|*}"; txt="${f#*|}"; [[ "$sev" == "$want" ]] || continue
                case "$sev" in crit) mk="${R}✗${NC}" ;; warn) mk="${Y}!${NC}" ;; info) mk="${GR}i${NC}" ;; *) mk="${G}✓${NC}" ;; esac
                bn_wrap "$mk" "$txt"
            done
        done
    fi
    local prev; prev=$(bench_compare_line)
    if [[ -n "$prev" ]]; then echo -e "  ${GR}$(hr 76)${NC}"; echo -e "  ${C}SINCE THE PREVIOUS TEST${NC}"; echo -e "$prev"; fi
}
bn_out() {    # mask mode: the last two numbers of every IPv4 address (and most of an IPv6 one), the destination / server host names and the owner become x, keeping the column widths
    if (( BN_MASK )); then
        local nm1; nm1=$(bget dest); valid_ip "$nm1" && nm1=""
        awk -v n1="$nm1" -v n2="$(bget host)" -v n3="$(bget owner)" -v kern="$(bget kernel)" '
            function xs(n,  r) { while (n-- > 0) r = r "x"; return r }
            function mask4(s,  out) {
                out = ""
                while (match(s, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
                    split(substr(s, RSTART, RLENGTH), o, ".")
                    out = out substr(s, 1, RSTART - 1) o[1] "." o[2] "." xs(length(o[3])) "." xs(length(o[4]))
                    s = substr(s, RSTART + RLENGTH)
                }
                return out s
            }
            function mask6(s,  out, t, k1, k2) {
                out = ""
                while (match(s, /[0-9a-fA-F]*::[0-9a-fA-F:]*[0-9a-fA-F]|[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F:]*[0-9a-fA-F]/)) {
                    t = substr(s, RSTART, RLENGTH); k1 = index(t, ":"); k2 = index(substr(t, k1 + 1), ":")
                    out = out substr(s, 1, RSTART - 1) (k2 ? substr(t, 1, k1 + k2) xs(length(t) - k1 - k2) : t)
                    s = substr(s, RSTART + RLENGTH)
                }
                return out s
            }
            function lit(s, f,  out, k) {          # every literal occurrence of a name (names shorter than 3 characters would damage ordinary words)
                if (length(f) < 3) return s
                out = ""
                while ((k = index(s, f)) > 0) { out = out substr(s, 1, k - 1) xs(length(f)); s = substr(s, k + length(f)) }
                return out s
            }
            function mask(s) { return mask6(mask4(lit(lit(lit(s, n1), n2), n3))) }
            { k = (kern != "" ? index($0, kern) : 0)               # a kernel version such as 6.8.0.1042 looks like an address: keep it
              if (k > 0) print mask(substr($0, 1, k - 1)) kern mask(substr($0, k + length(kern))); else print mask($0) }'
    else cat; fi
}

# ── history: save, compare with the previous run, and what the assistant changed in between ──
bench_write_file() {    # plain-text copy of the report (safe to paste anywhere); addresses are hidden while mask mode is on
    { bench_report_summary; echo; bench_report_details; } 2> /dev/null | sed 's/\x1b\[[0-9;]*m//g' | bn_out > "$1"
}
bench_save() {
    local port d f k um; port=$(bget port); d="$BENCH_DIR/$port"
    um=$(umask); umask 077                      # reports hold the real addresses: readable by root only
    mkdir -p "$d"; chmod 700 "$BENCH_DIR" "$d" 2> /dev/null
    [[ -f "$d/last.env" ]] && cp -f "$d/last.env" "$d/prev.env"
    for k in score grade ts mode p_avg p_jitter p_loss dl1_mbps dl4_mbps ul4_mbps bloat eng_ratio m_pmtu t_avg; do printf '%s=%s\n' "$k" "$(bget "$k")"; done > "$d/last.env"
    printf '%s\n' "${BN_RECO[@]}" > "$d/last.reco"
    f="$d/report-$(date -d "@$(bget ts)" +%Y%m%d-%H%M%S 2> /dev/null).txt"
    bench_write_file "$f"
    ls -1t "$d"/report-*.txt 2> /dev/null | tail -n +11 | while read -r old; do rm -f "$old"; done
    BN_REPORT_FILE="$f"
    umask "$um"
}
envget() { sed -n "s/^$2=//p" "$1" 2> /dev/null | head -1; }
bench_compare_line() {
    local port d prev; port=$(bget port); d="$BENCH_DIR/$port"; prev="$d/prev.env"
    [[ -f "$prev" ]] || return 0
    local ps pt ago
    ps=$(envget "$prev" score); pt=$(envget "$prev" ts); [[ "$ps" =~ ^[0-9]+$ && "$pt" =~ ^[0-9]+$ ]] || return 0
    ago=$(( ($(bget ts) - pt) / 60 ))
    local out="   Previous test: $(date -d "@$pt" '+%Y-%m-%d %H:%M' 2> /dev/null) (${ago} min earlier), score ${ps} → $(bget score) ($(awk -v a="$ps" -v b="$(bget score)" 'BEGIN { printf "%+d", b - a }'))"
    local k key lbl unit pv cv
    for k in "p_avg:latency:ms" "p_jitter:jitter:ms" "p_loss:loss:%" "dl4_mbps:download:Mbit/s" "ul4_mbps:upload:Mbit/s" "bloat:load latency:ms"; do
        IFS=: read -r key lbl unit <<< "$k"
        pv=$(envget "$prev" "$key"); cv=$(bget "$key")
        [[ -n "$pv" && -n "$cv" ]] && out+=$'\n'"   $(printf '%-13s' "$lbl") $(fmt1 "$pv") → $(fmt1 "$cv") $unit  ($(awk -v a="$pv" -v b="$cv" 'BEGIN { printf "%+.1f", b - a }'))"
    done
    if [[ -f "$TUNE_DIR/history.log" ]]; then
        local ch; ch=$(awk -F'|' -v t="$pt" '$1 > t { printf "%s%s", (n++ ? ", " : ""), $3 }' "$TUNE_DIR/history.log")
        [[ -n "$ch" ]] && out+=$'\n'"   Changed in between by the assistant: $ch"
    fi
    printf '%s' "$out"
}

# ── destination-side helper: the other end of the speed test ──
bench_fw_remove() {    # bench_fw_remove <tag>: every rule of this helper, in every firewall flavour
    local c
    for c in iptables ip6tables; do command -v "$c" > /dev/null 2>&1 && ipt_del_tag "$c" filter INPUT "$1"; done
    command -v nft > /dev/null 2>&1 && nft delete table inet "$1" 2> /dev/null
    return 0
}
bench_fw_sweep() {    # rules of a helper that was killed before it could clean up (SIGKILL, power loss); helpers that are still running are left alone
    local c t
    for c in iptables ip6tables; do command -v "$c" > /dev/null 2>&1 || continue
        for t in $($c -S INPUT 2> /dev/null | sed -n 's/.*--comment \(pfm_bench_[0-9]*\).*/\1/p' | sort -u); do
            kill -0 "${t#pfm_bench_}" 2> /dev/null && continue
            ipt_del_tag "$c" filter INPUT "$t"
        done
    done
    command -v nft > /dev/null 2>&1 && for t in $(nft list tables 2> /dev/null | awk '$3 ~ /^pfm_bench_[0-9]+$/ { print $3 }'); do
        kill -0 "${t#pfm_bench_}" 2> /dev/null && continue
        nft delete table inet "$t" 2> /dev/null
    done
    return 0
}
bench_fw_restrict() {    # bench_fw_restrict <port> <allowed ip> <tag> -> 0 only when the restriction is IN the firewall (checked, not assumed)
    local port="$1" allow="$2" tag="$3" c p main=iptables sel="ip saddr"
    [[ "$allow" == *:* ]] && { main=ip6tables; sel="ip6 saddr"; }
    if command -v "$main" > /dev/null 2>&1; then
        for c in iptables ip6tables; do
            command -v "$c" > /dev/null 2>&1 || continue
            for p in tcp udp; do
                if [[ "$c" == "$main" ]]; then
                    # final order: [ACCEPT the allowed address] [DROP everybody else] [the rest of the chain] - inserted at the very top, so no broad ACCEPT above can undo it
                    $c -I INPUT 1 -p "$p" --dport "$port" ! -s "$allow" -m comment --comment "$tag" -j DROP 2> /dev/null || return 1
                    $c -I INPUT 1 -p "$p" --dport "$port" -s "$allow" -m comment --comment "$tag" -j ACCEPT 2> /dev/null || return 1
                    $c -C INPUT -p "$p" --dport "$port" ! -s "$allow" -m comment --comment "$tag" -j DROP 2> /dev/null || return 1
                    $c -C INPUT -p "$p" --dport "$port" -s "$allow" -m comment --comment "$tag" -j ACCEPT 2> /dev/null || return 1
                else
                    $c -I INPUT 1 -p "$p" --dport "$port" -m comment --comment "$tag" -j DROP 2> /dev/null     # the other family: nobody (the helper does not even listen there)
                fi
            done
        done
        return 0
    fi
    command -v nft > /dev/null 2>&1 || return 1          # a host with nftables only
    nft add table inet "$tag" 2> /dev/null \
        && nft add chain inet "$tag" input '{ type filter hook input priority -100 ; policy accept ; }' 2> /dev/null \
        && nft add rule inet "$tag" input meta l4proto '{ tcp, udp }' th dport "$port" $sel != "$allow" drop 2> /dev/null \
        && nft list table inet "$tag" 2> /dev/null | grep -q drop && return 0
    nft delete table inet "$tag" 2> /dev/null; return 1
}
bench_port_busy() { ss -ltun "( sport = :$1 )" 2> /dev/null | tail -n +2 | grep -q .; }       # a TCP or UDP service already listens there
cmd_bench_server() {
    local port="${1:-5201}" allow="${2:-}" mins="${3:-15}" tag="pfm_bench_$$" ipf="" srv="" wd="" use="usage: pfm bench-server [port] [allowed client IP] [minutes 1-120]"
    valid_port "$port" || { echo -e "${R}'$port' is not a valid port.${NC}  $use"; return 1; }
    [[ "$mins" =~ ^[0-9]+$ ]] && (( mins >= 1 && mins <= 120 )) || { echo -e "${R}'$mins' minutes is not between 1 and 120.${NC}  $use"; return 1; }
    [[ -z "$allow" ]] || valid_ip "$allow" || { echo -e "${R}'$allow' is not an IP address.${NC}  $use"; return 1; }
    [[ $EUID -eq 0 ]] || { echo -e "${R}Run as root (it installs iperf3 and opens the port for ${allow:-anyone}).${NC}"; return 1; }
    ensure_tool iperf3 "speed-test helper" || return 1
    # the helper opens TCP AND UDP on the port: refuse one that something else uses (WireGuard / QUIC on a UDP port would lose its peers)
    if bench_port_busy "$port"; then echo -e "${R}Port ${port} is already used by another service (TCP or UDP).${NC} Choose a free port, e.g. pfm bench-server 5201"; return 1; fi
    bench_fw_sweep
    [[ -n "$allow" ]] && { ipf="-4"; [[ "$allow" == *:* ]] && ipf="-6"; }
    echo -e "\n  ${B}${C}PFM bench helper${NC}  iperf3 on port ${port} for ${mins} min"
    # the clean-up exists BEFORE the first firewall rule does
    bench_server_cleanup() { [[ -n "$wd" ]] && { pkill -P "$wd" 2> /dev/null; kill "$wd" 2> /dev/null; }; bench_fw_remove "$tag"; }
    trap 'kill "$srv" 2> /dev/null; bench_server_cleanup; echo -e "\n  ${GR}Helper stopped.${NC}"; exit 0' INT TERM HUP
    if [[ -n "$allow" ]]; then
        if ! bench_fw_restrict "$port" "$allow" "$tag"; then
            bench_server_cleanup; trap - INT TERM HUP
            echo -e "  ${R}Could not restrict port ${port} to ${allow} (no usable iptables / nftables rule), so the helper is NOT started - it would be open to everybody.${NC}"
            echo -e "  ${GR}If you accept that anyone who can reach the port may use your bandwidth for ${mins} minutes: pfm bench-server ${port}${NC}"
            return 1
        fi
        echo -e "  ${G}Only ${allow} may connect${NC} ${GR}(verified in the firewall; the rules are removed when this stops)${NC}"
        ( trap '' HUP INT; sleep $(( mins * 60 + 30 )); bench_fw_remove "$tag" ) > /dev/null 2>&1 & wd=$!       # outlives a kill -9 of this process
    else echo -e "  ${Y}No client IP given: anyone who can reach port ${port} can use your bandwidth until this stops.${NC}"; fi
    echo -e "  ${G}Ready.${NC} On the PFM server choose the full test and enter port ${port}. Ctrl+C stops it.\n"
    timeout "${mins}m" iperf3 -s $ipf -p "$port" & srv=$!       # in the background + wait: a signal must run the cleanup at once
    wait "$srv"
    bench_server_cleanup; trap - INT TERM HUP
    echo -e "\n  ${GR}Helper stopped.${NC}"
}
bench_peer_help() {    # shown when the helper is not reachable
    local src; src=$(bget r_src)
    echo -e "\n  ${Y}The speed-test helper is not reachable on $(bget ip):${1}.${NC}"
    echo -e "  ${GR}A tunnel can only be speed-tested together with the other end. On the DESTINATION server run (as root):${NC}\n"
    echo -e "    ${W}bash <(curl -sL ${PFM_REPO_RAW}/pfm.sh) bench-server ${1} ${src:-}${NC}\n"
    echo -e "  ${GR}It installs iperf3 if needed, accepts only ${src:-your IP}, and stops by itself after 15 minutes.${NC}"
    echo -e "  ${GR}(If this server sits behind NAT, give the public IP it appears from instead of ${src:-that address}.)${NC}"
    echo -e "  ${GR}Needs TCP and UDP ${1} reachable from ${src:-here} (cloud firewall / security group too).${NC}"
}

# ── menu + CLI ──
bench_show() {    # interactive viewer for the report of the test that just ran
    local page=1 act n
    while true; do
        clear
        if [[ $page == 1 ]]; then bench_report_summary | bn_out; else bench_report_details | bn_out; fi
        echo -e "\n  ${GR}$([[ $page == 1 ]] && echo 'd details' || echo 'd summary') · m mask IPs ($([[ $BN_MASK == 1 ]] && echo on || echo off)) · s file · r again · $( ((${#BN_RECO[@]})) && echo "1-${#BN_RECO[@]} apply · " )0 back${NC}"
        echo -ne "  ${C}>${NC} "; read -r act || return 0
        case "$act" in
            d) page=$(( 3 - page )) ;;
            m) BN_MASK=$(( 1 - BN_MASK )); bench_write_file "$BN_REPORT_FILE" ;;
            s) bench_write_file "$BN_REPORT_FILE"
               echo -e "  ${G}Saved: ${BN_REPORT_FILE}${NC}  ${GR}(plain text, $( ((BN_MASK)) && echo 'IP addresses hidden' || echo 'contains the real IP addresses - press m first to hide them'))${NC}"; pause ;;
            r) return 2 ;;
            ""|0|q) return 0 ;;
            *) if [[ "$act" =~ ^[0-9]+$ ]] && (( act >= 1 && act <= ${#BN_RECO[@]} )); then
                   if assist_do "${BN_RECO[act-1]%%|*}" "$(bget port)"; then echo -e "\n  ${G}Done.${NC} Press ${W}r${NC} to run the test again and see what changed."
                   else echo -e "\n  ${Y}Nothing was changed${NC} ${GR}(see the message above).${NC}"; fi
                   pause
               fi ;;
        esac
    done
}
menu_bench() {
    local port="$1" pp="" mode ret inet=0 a
    [[ -f "$PORTS_DIR/$port" ]] || return
    while true; do
        header
        local P_DEST="" P_DPORT="$port" P_METHOD="iptables"; source "$PORTS_DIR/$port"
        echo -e "  ${B}${W}Bench Test${NC}  ${GR}:${port} → ${P_DEST}:${P_DPORT} [${P_METHOD}]${NC}\n"
        echo -e "  ${W}1)${NC} Quick test      ${GR}~40 s  latency, jitter, loss, MTU, route, live traffic${NC}"
        echo -e "  ${W}2)${NC} Full test       ${GR}~3 min  + 60 s stability, speed test (needs the helper on the destination)${NC}"
        echo -e "  ${W}3)${NC} Last report     ${GR}and what changed since the test before${NC}"
        echo -e "  ${W}4)${NC} Set up the destination helper ${GR}(shows the one command to run there)${NC}"
        echo -e "  ${W}0)${NC} Back"
        echo -ne "\n  ${C}Select:${NC} "; read -r opt || return 0
        case "$opt" in
            1|2)
                mode=quick; pp=0; inet=0
                if [[ "$opt" == 2 ]]; then
                    mode=full
                    echo -ne "\n  ${C}Speed-test helper port on the destination [5201], or ${W}s${C} to skip the speed test:${NC} "; read -r pp || return 0
                    if [[ "$pp" == s || "$pp" == S ]]; then
                        pp=0
                        echo -ne "  ${C}Instead measure this server's own internet speed (downloads up to 100 MB from Cloudflare)? (y/N):${NC} "; read -r a
                        [[ "$a" == y || "$a" == Y ]] && inet=1
                    else pp="${pp:-5201}"; [[ "$pp" =~ ^[0-9]+$ ]] && valid_port "$pp" || pp=0; fi
                    if (( pp > 0 )); then
                        bench_prepare "$port" > /dev/null
                        ensure_tool iperf3 "speed test" || pp=0
                        if (( pp > 0 )) && ! iperf_peer_ok "$(bget ip)" "$pp"; then
                            bench_peer_help "$pp"
                            echo -ne "\n  ${C}Enter when it is running, ${W}s${C} to skip the speed test:${NC} "; read -r a
                            if [[ "$a" == s || "$a" == S ]] || ! iperf_peer_ok "$(bget ip)" "$pp"; then echo -e "  ${Y}Helper still not reachable - running without the speed test.${NC}"; pp=0; sleep 1; fi
                        fi
                    fi
                fi
                ensure_tool ping "latency test" || { echo -e "  ${R}ping is required.${NC}"; pause; continue; }
                bench_run "$port" "$mode" "$pp" "$inet" || { pause; continue; }
                bench_save
                bench_show; ret=$?
                while [[ $ret == 2 ]]; do                       # r / applied an action: run again
                    bench_run "$port" "$mode" "$pp" "$inet" || break
                    bench_save; bench_show; ret=$?
                done ;;
            3)
                local lf; lf=$(ls -1t "$BENCH_DIR/$port"/report-*.txt 2> /dev/null | head -1)
                if [[ -n "$lf" ]]; then header; cat "$lf" | bn_out; else echo -e "  ${Y}No saved report yet.${NC}"; fi
                pause ;;
            4) bench_prepare "$port" > /dev/null; bench_peer_help 5201; pause ;;
            0|"") return ;;
        esac
    done
}
cmd_bench() {    # pfm bench <port> [quick|full] [--peer PORT] [--inet] [--yes] [--mask]
    check_root
    local port="${1:-}" mode=quick pp=0 inet=0 use="usage: pfm bench <port> [quick|full] [--peer PORT] [--inet] [--yes] [--mask]"; shift 2> /dev/null
    [[ -f "$PORTS_DIR/$port" ]] || { echo "$use"; return 1; }
    while [[ $# -gt 0 ]]; do
        case "$1" in
            quick|full) mode="$1" ;; --peer) pp="${2:-5201}"; shift ;; --inet) inet=1 ;; --yes|-y) PFM_YES=1 ;; --mask) BN_MASK=1 ;;
            *) echo "unknown option '$1'"; echo "$use"; return 1 ;;
        esac; shift
    done
    [[ "$pp" =~ ^[0-9]+$ ]] && { (( pp == 0 )) || valid_port "$pp"; } || { echo "--peer needs a port number (1-65535)"; echo "$use"; return 1; }
    ensure_tool ping "latency test" || { echo "ping is required"; return 1; }
    if (( pp > 0 )); then     # the same checks the menu makes: a missing helper must say so instead of turning a "full" report into a quick one
        bench_prepare "$port" > /dev/null || { echo -e "  ${R}Cannot start the test: tunnel not found, destination does not resolve, or no route to it.${NC}"; return 1; }
        if ! ensure_tool iperf3 "speed test"; then echo -e "  ${Y}Without iperf3 there is no speed test - continuing without it.${NC}"; pp=0
        elif ! iperf_peer_ok "$(bget ip)" "$pp"; then bench_peer_help "$pp"; echo -e "\n  ${Y}Helper not reachable - continuing without the speed test.${NC}"; pp=0; fi
    fi
    bench_run "$port" "$mode" "$pp" "$inet" || return 1
    bench_save
    echo; { bench_report_summary; echo; bench_report_details; } | bn_out
    echo -e "\n  ${GR}Saved: ${BN_REPORT_FILE}${NC}"
}
# @@END bench@@
# @@CHUNK assist@@
# ═══════════════ OPTIMIZATION ASSISTANT ═══════════════
# Every change is recorded (original value first), applied live, persisted, re-applied by `pfm restore`/`pfm sync`
# and can be reverted. Nothing is touched without showing what and why.
RESOLV_CONF="${PFM_RESOLV_CONF:-/etc/resolv.conf}"
SYSCTL_D_FILE="${PFM_SYSCTL_D_FILE:-/etc/sysctl.d/99-pfm.tune.conf}"
MODLOAD_FILE="${PFM_MODLOAD_FILE:-/etc/modules-load.d/bbr.conf}"
PFM_ROUTE_PROTO=77         # routes the assistant creates carry this protocol number, so only they are ever removed

tune_init() { mkdir -p "$TUNE_DIR"; local f; for f in history.log sysctl.orig sysctl.conf nic.conf nic.orig mss.ports misc.orig; do [[ -e "$TUNE_DIR/$f" ]] || : > "$TUNE_DIR/$f"; done; }
tune_hist() { tune_init; echo "$(date +%s)|$1|$2" >> "$TUNE_DIR/history.log"; log "TUNE $1: $2"; }
kv_get() { awk -F= -v k="$2" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$1" 2> /dev/null; }
kv_has() { awk -F= -v k="$2" '$1 == k { f = 1 } END { exit !f }' "$1" 2> /dev/null; }
kv_set() {    # replaced as a whole: a kill or a full disk must never leave a half-written (empty) record of the original values
    local f="$1" k="$2" v="$3" t; touch "$f" 2> /dev/null; t=$(mktemp "$f.XXXXXX") || return 1
    { awk -F= -v k="$k" '$1 != k' "$f"; echo "$k=$v"; } > "$t" && mv -f "$t" "$f" || { rm -f "$t"; return 1; }
}
kv_del() { local f="$1" t; [[ -f "$f" ]] || return 0; t=$(mktemp "$f.XXXXXX") || return 1; awk -F= -v k="$2" '$1 != k' "$f" > "$t" && mv -f "$t" "$f" || { rm -f "$t"; return 1; }; }
port_set() { local f="$PORTS_DIR/$1" k="$2" v="$3"; [[ -f "$f" ]] || return 1; if grep -q "^$k=" "$f"; then sed -i "s|^$k=.*|$k=\"$v\"|" "$f"; else echo "$k=\"$v\"" >> "$f"; fi; }
port_unset() { sed -i "/^$2=/d" "$PORTS_DIR/$1" 2> /dev/null; }

# ── kernel tunables: original value remembered, change persisted, re-applied at boot and by sync ──
TUNE_OK=0; TUNE_NO=0       # settings really written / refused since tune_count_reset: the closing line must tell the truth
tune_count_reset() { TUNE_OK=0; TUNE_NO=0; }
tune_sysctl() {    # tune_sysctl <key> <value> -> 0 applied · 1 not in this kernel · 2 refused (container / read-only / no room to record the original)
    local k="$1" v="$2" cur
    sys_has "$k" || return 1
    tune_init; cur=$(sys_get "$k")
    # the original is recorded FIRST: a change that cannot be undone is not made
    kv_has "$TUNE_DIR/sysctl.orig" "$k" || kv_set "$TUNE_DIR/sysctl.orig" "$k" "$cur" || { TUNE_NO=$((TUNE_NO + 1)); return 2; }
    if [[ "$cur" != "$v" ]]; then sys_set "$k" "$v" || { TUNE_NO=$((TUNE_NO + 1)); return 2; }; fi
    if ! kv_set "$TUNE_DIR/sysctl.conf" "$k" "$v"; then [[ "$cur" != "$v" ]] && sys_set "$k" "$cur"; TUNE_NO=$((TUNE_NO + 1)); return 2; fi
    tune_sysctl_d
    TUNE_OK=$((TUNE_OK + 1))
    return 0
}
tune_done() {    # the closing line of an action: "Done" only when something was really changed
    if (( TUNE_NO > 0 && TUNE_OK == 0 )); then echo -e "  ${R}Nothing was changed: this system refuses the settings (container or read-only /proc/sys).${NC}"; return 1
    elif (( TUNE_NO > 0 )); then echo -e "  ${Y}Done - but ${TUNE_NO} setting(s) were refused by this system.${NC}"
    else echo -e "  ${G}Done.${NC}"; fi
}
tune_raise() {    # only ever raises a numeric tunable
    local k="$1" v="$2" cur; cur=$(sys_get "$k")
    [[ "$cur" =~ ^[0-9]+$ ]] || return 1
    (( cur >= v )) && return 0
    tune_sysctl "$k" "$v"
}
tune_raise_tcpmem() {    # tune_raise_tcpmem <net.ipv4.tcp_rmem|tcp_wmem> <max>: only the third field (the auto-tuning ceiling) is raised; min and default stay
    local k="$1" want="$2" a b c
    read -r a b c <<< "$(sys_get "$k")"
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ ]] || return 1
    (( c >= want )) && return 0
    tune_sysctl "$k" "$a $b $want"
}
tune_sysctl_d() {    # the same settings for the kernel's own boot-time loader (applied after /etc/sysctl.d/99-pfm.conf)
    local t
    if [[ -s "$TUNE_DIR/sysctl.conf" ]]; then
        t=$(mktemp "$SYSCTL_D_FILE.XXXXXX") || return 0
        { echo "# Written by the PFM Optimization Assistant. 'pfm optimize' -> Status & revert removes it."; sed 's/=/ = /' "$TUNE_DIR/sysctl.conf"; } > "$t" && chmod 644 "$t" && mv -f "$t" "$SYSCTL_D_FILE" || rm -f "$t"
    else rm -f "$SYSCTL_D_FILE"; fi
}
tune_sysctl_wanted() {    # tune_sysctl_wanted <key> <stored value> -> 0 = the live value should be written again.
    local k="$1" want="$2" live orig lc wc          # A number is only ever RAISED (a higher value an admin chose stays); of tcp_rmem / tcp_wmem only the ceiling is ours;
    live=$(sys_get "$k"); [[ "$live" == "$want" ]] && return 1       # anything else (congestion control, queue) is put back only when it is back at the value it had before we changed it.
    if [[ "$want" =~ ^[0-9]+$ && "$live" =~ ^[0-9]+$ ]]; then (( live < want )); return; fi
    if [[ "$want" =~ ^[0-9]+\ [0-9]+\ [0-9]+$ && "$live" =~ ^[0-9]+\ [0-9]+\ [0-9]+$ ]]; then lc="${live##* }"; wc="${want##* }"; (( lc < wc )); return; fi
    orig=$(kv_get "$TUNE_DIR/sysctl.orig" "$k"); [[ -n "$live" && "$live" == "$orig" ]]
}
tune_sysctl_write_stored() {    # a multi-field window setting keeps the minimum / default somebody else chose; only its ceiling is ours
    local k="$1" want="$2" a b c
    if [[ "$want" =~ ^[0-9]+\ [0-9]+\ [0-9]+$ ]]; then read -r a b c <<< "$(sys_get "$k")"; [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] && want="$a $b ${want##* }"; fi
    sys_set "$k" "$want"
}
tune_sysctl_restore() { local k v; [[ -s "$TUNE_DIR/sysctl.conf" ]] || return 0; while IFS='=' read -r k v; do [[ -n "$k" ]] && tune_sysctl_wanted "$k" "$v" && tune_sysctl_write_stored "$k" "$v"; done < "$TUNE_DIR/sysctl.conf"; return 0; }
tune_sysctl_drift() {    # keys that lost the setting the assistant made (somebody ran sysctl -p / a boot script reset them) - a value an admin chose on purpose is no drift
    local k v; [[ -s "$TUNE_DIR/sysctl.conf" ]] || return 0
    while IFS='=' read -r k v; do [[ -n "$k" ]] && tune_sysctl_wanted "$k" "$v" && echo "$k"; done < "$TUNE_DIR/sysctl.conf"; return 0
}
tune_sysctl_revert() {
    local k v n=0
    [[ -s "$TUNE_DIR/sysctl.orig" ]] && while IFS='=' read -r k v; do [[ -n "$k" ]] && sys_set "$k" "$v" 2> /dev/null && n=$((n + 1)); done < "$TUNE_DIR/sysctl.orig"
    : > "$TUNE_DIR/sysctl.orig"; : > "$TUNE_DIR/sysctl.conf"; tune_sysctl_d; echo "$n"
}
sysctl_row() {    # sysctl_row <label> <key> <wanted> [raise]  - one line of a plan table; prints nothing when already fine
    local label="$1" k="$2" want="$3" mode="${4:-set}" cur
    sys_has "$k" || return 0
    cur=$(sys_get "$k")
    if [[ "$mode" == raise ]]; then [[ "$cur" =~ ^[0-9]+$ ]] && (( cur >= want )) && return 0
    else [[ "$cur" == "$want" ]] && return 0; fi
    printf "   %-26s %-22s -> %s\n" "$label" "${cur:0:22}" "$want"
}
sysctl_row_tcpmem() {    # sysctl_row_tcpmem <label> <key> <wanted max> - the third field of tcp_rmem / tcp_wmem
    local c; sys_has "$2" || return 0
    c=$(sys_get "$2" | awk '{ print $3 }')
    [[ "$c" =~ ^[0-9]+$ ]] && (( c >= $3 )) && return 0
    printf "   %-26s %-22s -> %s\n" "$1" "${c:-?}" "$3"
}

# ── congestion control ──
bbr_available() {
    local a; a=$(sys_get net.ipv4.tcp_available_congestion_control)
    if [[ "$a" != *bbr* ]]; then modprobe tcp_bbr 2> /dev/null; a=$(sys_get net.ipv4.tcp_available_congestion_control); fi
    [[ "$a" == *bbr* ]]
}
assist_bbr() {
    local cc qd dev swap=""; cc=$(sys_get net.ipv4.tcp_congestion_control); qd=$(sys_get net.core.default_qdisc); dev=$(nic_default_dev)
    [[ -n "$dev" && -n "$(nic_qdisc_targets "$dev")" ]] && swap="$dev"
    echo -e "\n  ${B}${W}BBR + fq${NC}\n"
    echo -e "  ${GR}Now: congestion control ${cc:-?}, default qdisc ${qd:-n/a}${NC}"
    echo -e "  ${GR}BBR keeps TCP fast on long or lossy paths and keeps queues short. It acts on connections this server${NC}"
    echo -e "  ${GR}terminates itself (realm / HAProxy tunnels); iptables-forwarded connections are only NAT-ed.${NC}\n"
    if ! bbr_available; then echo -e "  ${R}BBR is not available here (kernel older than 4.9, or a container without the module).${NC}"; return 1; fi
    if [[ "$cc" == bbr && "$qd" == fq && -z "$swap" ]]; then echo -e "  ${G}Already active.${NC}"; return 0; fi
    [[ -n "$swap" ]] && echo -e "  ${GR}Also: the queue of $swap is the kernel default ($(nic_root_qdisc "$swap")) - it is switched to fq right away if tc allows it (a queue you configured is never touched).${NC}\n"
    confirm "Enable BBR + fq now and keep it after reboot?" y || return 1
    local r; tune_count_reset
    tune_sysctl net.core.default_qdisc fq; r=$?
    case $r in 1) echo -e "  ${Y}fq is not available in this kernel - BBR still works (it paces itself).${NC}" ;; 2) echo -e "  ${Y}default qdisc cannot be changed here.${NC}" ;; esac
    tune_sysctl net.ipv4.tcp_congestion_control bbr; r=$?
    if (( r != 0 )); then echo -e "  ${R}Could not switch the congestion control (${r}).${NC}"; return 1; fi
    grep -q tcp_bbr "$MODLOAD_FILE" 2> /dev/null || { mkdir -p "$(dirname "$MODLOAD_FILE")"; echo tcp_bbr > "$MODLOAD_FILE"; }
    if [[ -n "$swap" ]]; then nic_set_qdisc "$dev" || echo -e "  ${Y}tc did not accept the new queue for $dev - it keeps its current one (new devices and queues still get fq).${NC}"; fi
    tune_hist cc "BBR + fq enabled (was ${cc:-?}/${qd:-?})"
    echo -e "  ${G}BBR is active${NC} ${GR}($(sys_get net.ipv4.tcp_congestion_control), qdisc $(sys_get net.core.default_qdisc)). New connections use it; existing ones keep their old algorithm.${NC}"
}

# ── buffers sized for the path (bandwidth x delay) ──
assist_buffers() {    # assist_buffers [rtt_ms] [target Mbit/s]
    local rtt="${1:-}" rate="${2:-1000}" need pick cur
    [[ -n "$rtt" ]] || rtt=150
    need=$(awk -v r="$rtt" -v m="$rate" 'BEGIN { printf "%.0f", 2 * m * 1e6 / 8 * r / 1000 }')
    pick=16777216; local p; for p in 16777216 33554432 67108864 134217728; do pick=$p; (( p >= need )) && break; done
    cur=$(sys_get net.ipv4.tcp_rmem | awk '{ print $3 }')
    echo -e "\n  ${B}${W}TCP buffers${NC}\n"
    echo -e "  ${GR}A single connection can only use (window / latency): to fill ${rate} Mbit/s at ${rtt} ms it needs a window of about $(human_bytes $(( need / 2 ))).${NC}"
    echo -e "  ${GR}Now: TCP receive-buffer limit $(( ${cur:-0} / 1048576 )) MB   ->   proposed $(( pick / 1048576 )) MB (limits only - memory is used when a connection needs it; values are only ever raised).${NC}\n"
    if [[ "$cur" =~ ^[0-9]+$ ]] && (( cur >= pick )); then echo -e "  ${G}Already large enough.${NC}"; return 0; fi
    confirm "Raise the limits to $(( pick / 1048576 )) MB?" y || return 1
    tune_count_reset
    tune_raise net.core.rmem_max "$pick"; tune_raise net.core.wmem_max "$pick"
    tune_raise_tcpmem net.ipv4.tcp_rmem "$pick"; tune_raise_tcpmem net.ipv4.tcp_wmem "$pick"
    (( TUNE_OK > 0 )) && tune_hist buffers "TCP buffer limit $(( ${cur:-0} / 1048576 )) MB -> $(( pick / 1048576 )) MB (${rtt} ms x ${rate} Mbit/s)"
    tune_done
}

# ── limits that silently cap busy forwarders ──
limits_ct_target() {    # the connection-tracking limit this much RAM deserves
    local mem ct
    mem=$(awk '/MemTotal/ { printf "%d", $2 / 1024 }' /proc/meminfo)
    ct=131072; (( mem >= 1000 )) && ct=262144; (( mem >= 2000 )) && ct=524288; (( mem >= 4000 )) && ct=1048576; (( mem >= 8000 )) && ct=2097152
    echo "$ct"
}
ct_hash_want() {    # prints "<current> <wanted>" when the conntrack hash table is smaller than a quarter of the (new) limit and the module lets us resize it
    local hs="${PFM_CT_HASHSIZE:-/sys/module/nf_conntrack/parameters/hashsize}" cmax hcur ct
    [[ -w "$hs" ]] || return 0
    ct=$(limits_ct_target); cmax=$(sys_get net.netfilter.nf_conntrack_max); hcur=$(cat "$hs" 2> /dev/null)
    [[ "$cmax" =~ ^[0-9]+$ && "$hcur" =~ ^[0-9]+$ ]] || return 0
    (( cmax < ct )) && cmax=$ct
    (( hcur < cmax / 4 )) && echo "$hcur $(( cmax / 4 ))"
    return 0
}
limits_plan() {    # prints the rows that would change
    local ct hw; ct=$(limits_ct_target)
    sysctl_row "connection tracking" net.netfilter.nf_conntrack_max "$ct" raise
    hw=$(ct_hash_want); [[ -n "$hw" ]] && printf "   %-26s %-22s -> %s\n" "conntrack hash (until reboot)" "${hw% *}" "${hw#* }"
    sysctl_row "listen backlog" net.core.somaxconn 8192 raise
    sysctl_row "SYN backlog" net.ipv4.tcp_max_syn_backlog 8192 raise
    sysctl_row "receive queue per CPU" net.core.netdev_max_backlog 16384 raise
    sysctl_row "open files (system)" fs.file-max 1048576 raise
}
limits_apply() {
    local ct hw hs="${PFM_CT_HASHSIZE:-/sys/module/nf_conntrack/parameters/hashsize}"
    ct=$(limits_ct_target)
    hw=$(ct_hash_want)                      # decided BEFORE the limit is raised: the plan and the action see the same numbers
    tune_raise net.netfilter.nf_conntrack_max "$ct"
    tune_raise net.core.somaxconn 8192; tune_raise net.ipv4.tcp_max_syn_backlog 8192
    tune_raise net.core.netdev_max_backlog 16384; tune_raise fs.file-max 1048576
    # a hash table sized for the larger limit keeps lookups fast; the original size is remembered so that "revert" can give it back
    if [[ -n "$hw" ]]; then
        tune_init; kv_has "$TUNE_DIR/misc.orig" hashsize || kv_set "$TUNE_DIR/misc.orig" hashsize "${hw% *}" || return 0
        { echo "${hw#* }" > "$hs"; } 2> /dev/null && TUNE_OK=$((TUNE_OK + 1))
    fi
    return 0
}
tune_misc_revert() {    # settings that are not sysctl keys (the conntrack hash size); prints how many were put back
    local n=0 v hs="${PFM_CT_HASHSIZE:-/sys/module/nf_conntrack/parameters/hashsize}"
    v=$(kv_get "$TUNE_DIR/misc.orig" hashsize)
    [[ "$v" =~ ^[0-9]+$ ]] && [[ -w "$hs" ]] && { echo "$v" > "$hs"; } 2> /dev/null && n=$((n + 1))
    [[ -f "$TUNE_DIR/misc.orig" ]] && : > "$TUNE_DIR/misc.orig"
    echo "$n"
}
assist_limits() {
    local plan; plan=$(limits_plan)
    echo -e "\n  ${B}${W}Connection & queue limits${NC}\n"
    if [[ -z "$plan" ]]; then echo -e "  ${G}All limits are already at or above the recommendation.${NC}"; return 0; fi
    echo -e "  ${GR}A busy forwarder hits these before it hits the bandwidth: new connections are dropped when they are full.${NC}\n"
    printf "   ${GR}%-26s %-22s    %s${NC}\n" "setting" "now" "proposed"; echo "$plan"; echo ""
    confirm "Apply (values are only ever raised)?" y || return 1
    tune_count_reset; limits_apply
    (( TUNE_OK > 0 )) && tune_hist limits "connection / queue limits raised"
    tune_done
}

# ── network card ──
nic_default_dev() {
    [[ -n "${PFM_DEFAULT_DEV:-}" ]] && { echo "$PFM_DEFAULT_DEV"; return; }
    ip -o route show default 2> /dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i+1); exit } }'
}
nic_is_phys() { [[ -e "$SYSFS_NET/$1/device" ]]; }
nic_rxq() { ls -d "$SYSFS_NET/$1"/queues/rx-* 2> /dev/null | wc -l; }
cpu_mask_hex() {    # n CPUs -> kernel cpumask: 32-bit hex groups, most significant first
    local rem="$1" b out="" i; local -a parts=()
    while (( rem > 0 )); do b=$(( rem >= 32 ? 32 : rem )); parts+=("$(printf '%x' $(( (1 << b) - 1 )))"); rem=$(( rem - b )); done
    for (( i = ${#parts[@]} - 1; i >= 0; i-- )); do out+="${parts[i]},"; done
    echo "${out%,}"
}
nic_feature() { ethtool -k "$1" 2> /dev/null | awk -F': ' -v f="$2" '$1 == f { sub(/ .*/, "", $2); print $2; exit }'; }
nic_feature_fixed() { ethtool -k "$1" 2> /dev/null | awk -F': ' -v f="$2" '$1 == f && /\[fixed\]/ { r = 1 } END { exit !r }'; }
nic_root_qdisc() { tc qdisc show dev "$1" root 2> /dev/null | awk 'NR == 1 { print $2 }'; }
nic_qdisc_targets() {    # the queues of <dev> that are the kernel's plain default and would become fq, one "<target> <kind>" per line: "root pfifo_fast" / ":3 pfifo_fast".
    local dev="$1" all root              # Anything somebody configured (fq_codel, cake, htb, netem, tbf ...) and virtual noqueue devices are left alone.
    command -v tc > /dev/null 2>&1 || return 0
    all=$(tc qdisc show dev "$dev" 2> /dev/null) || return 0
    root=$(awk '/ root( |$)/ { print $2; exit }' <<< "$all")
    case "$root" in
        pfifo_fast|pfifo) echo "root $root" ;;
        mq) awk '$2 ~ /^(pfifo_fast|pfifo)$/ { for (i = 1; i < NF; i++) if ($i == "parent") print $(i + 1), $2 }' <<< "$all" ;;
    esac
}
nic_qdisc_wanted() { [[ "$(sys_get net.ipv4.tcp_congestion_control)" == bbr ]]; }
nic_set_qdisc() {    # make the kernel-default queue of <dev> fq (BBR's partner); multi-queue cards get it on every queue
    local dev="$1" targets t k first
    command -v tc > /dev/null 2>&1 || return 1
    targets=$(nic_qdisc_targets "$dev"); [[ -n "$targets" ]] || return 0
    tune_init
    first=$(awk 'NR == 1 { print $2 }' <<< "$targets")
    kv_has "$TUNE_DIR/nic.orig" "qdisc:$dev" || kv_set "$TUNE_DIR/nic.orig" "qdisc:$dev" "$([[ "$(nic_root_qdisc "$dev")" == mq ]] && echo mq || echo root) $first"      # the first original wins, even when somebody changes the queue later
    while read -r t k; do
        [[ -n "$t" ]] || continue
        if [[ "$t" == root ]]; then tc qdisc replace dev "$dev" root fq 2> /dev/null || return 1
        else tc qdisc replace dev "$dev" parent "$t" fq 2> /dev/null || return 1; fi
    done <<< "$targets"
    kv_set "$TUNE_DIR/nic.conf" "qdisc:$dev" fq
    return 0
}

nic_ring() {    # nic_ring <dev> -> "<max rx> <max tx> <current rx> <current tx>" (zeros when the driver has no ring settings)
    ethtool -g "$1" 2> /dev/null | awk '/^Pre-set maximums/ { s = 1 } /^Current hardware/ { s = 2 } /^RX:/ { if (s == 1) rm = $2; if (s == 2) rc = $2 } /^TX:/ { if (s == 1) tm = $2; if (s == 2) tc = $2 } END { print rm + 0, tm + 0, rc + 0, tc + 0 }'
}
nic_norm_mask() { local m="${1//,/}"; m="${m,,}"; m="${m#"${m%%[!0]*}"}"; echo "${m:-0}"; }      # the kernel pads a cpumask with zeros, we store it without
nic_wanted_features() { printf '%s\n' "generic-receive-offload gro on" "generic-segmentation-offload gso on" "tcp-segmentation-offload tso on" "large-receive-offload lro off"; }
nic_scan() {    # nic_scan <dev> -> one-line facts
    local dev="$1" drv speed rxq cpus drops
    drv=$(ethtool -i "$dev" 2> /dev/null | awk '/^driver:/ { print $2 }')
    speed=$(cat "$SYSFS_NET/$dev/speed" 2> /dev/null); [[ "$speed" =~ ^[0-9]+$ ]] || speed=0
    rxq=$(nic_rxq "$dev"); cpus=$(nproc 2> /dev/null || echo 1)
    drops=$(( $(cat "$SYSFS_NET/$dev/statistics/rx_dropped" 2> /dev/null || echo 0) + $(cat "$SYSFS_NET/$dev/statistics/rx_missed_errors" 2> /dev/null || echo 0) ))
    echo "dev=$dev driver=${drv:-?} speed=$speed rxq=$rxq cpus=$cpus drops=$drops mtu=$(cat "$SYSFS_NET/$dev/mtu" 2> /dev/null) gro=$(nic_feature "$dev" generic-receive-offload) gso=$(nic_feature "$dev" generic-segmentation-offload) tso=$(nic_feature "$dev" tcp-segmentation-offload) lro=$(nic_feature "$dev" large-receive-offload)"
}
nic_plan() {    # nic_plan <dev> [fq] -> rows describing what would change ("fq" = BBR is about to be enabled, so the queue is part of the plan too)
    local dev="$1" want_fq="${2:-}" cpus rxq feat f st cur sq    # nic_apply does exactly this and nothing more
    cpus=$(nproc 2> /dev/null || echo 1); rxq=$(nic_rxq "$dev")
    if (( rxq == 1 && cpus > 1 )) && [[ -e "$SYSFS_NET/$dev/queues/rx-0/rps_cpus" ]]; then
        if [[ "$(nic_norm_mask "$(cat "$SYSFS_NET/$dev/queues/rx-0/rps_cpus" 2> /dev/null)")" == 0 ]]; then
            printf "   %-30s %-14s -> %s\n" "$dev: spread RX over CPUs (RPS)" "1 CPU handles all" "$cpus CPUs"
            sysctl_row "RPS flow table" net.core.rps_sock_flow_entries 32768 raise
        fi
    fi
    if [[ -n "$want_fq" ]] || nic_qdisc_wanted; then
        [[ -n "$(nic_qdisc_targets "$dev")" ]] && printf "   %-30s %-14s -> %s\n" "$dev: queue (live, no reboot)" "$(nic_root_qdisc "$dev")" "fq"
    fi
    sq=$(softnet_stat | awk '{ print $2 }'); [[ "$sq" =~ ^[0-9]+$ ]] && (( sq > 0 )) && sysctl_row "NAPI budget (CPU squeezed)" net.core.netdev_budget 600 raise
    command -v ethtool > /dev/null 2>&1 || return 0
    while read -r feat f st; do
        nic_feature_fixed "$dev" "$feat" && continue
        cur=$(nic_feature "$dev" "$feat")
        [[ -n "$cur" && "$cur" != "$st" ]] && printf "   %-30s %-14s -> %s\n" "$dev: $feat" "$cur" "$st"
    done < <(nic_wanted_features)
    return 0
}
nic_apply() {    # nic_apply <dev> [1|only_rings]: exactly what nic_plan lists; 1 = the ring buffers as well, only_rings = nothing but those
    local dev="$1" mode="${2:-0}" cpus rxq q mask feat f st cur okq=0 sq
    cpus=$(nproc 2> /dev/null || echo 1); rxq=$(nic_rxq "$dev"); tune_init
    if [[ "$mode" != only_rings ]]; then
        if (( rxq == 1 && cpus > 1 )) && [[ -e "$SYSFS_NET/$dev/queues/rx-0/rps_cpus" ]] && [[ "$(nic_norm_mask "$(cat "$SYSFS_NET/$dev/queues/rx-0/rps_cpus" 2> /dev/null)")" == 0 ]]; then
            mask=$(cpu_mask_hex "$cpus")             # (a card that already spreads its work, or has a mask somebody chose, is left alone)
            for q in "$SYSFS_NET/$dev"/queues/rx-*; do
                kv_has "$TUNE_DIR/nic.orig" "rps:$dev:${q##*/}" || kv_set "$TUNE_DIR/nic.orig" "rps:$dev:${q##*/}" "$(cat "$q/rps_cpus" 2> /dev/null)"
                kv_has "$TUNE_DIR/nic.orig" "rpsflow:$dev:${q##*/}" || kv_set "$TUNE_DIR/nic.orig" "rpsflow:$dev:${q##*/}" "$(cat "$q/rps_flow_cnt" 2> /dev/null)"
                if { echo "$mask" > "$q/rps_cpus"; } 2> /dev/null; then okq=1; TUNE_OK=$((TUNE_OK + 1)); else TUNE_NO=$((TUNE_NO + 1)); continue; fi
                { echo $(( 32768 / rxq )) > "$q/rps_flow_cnt"; } 2> /dev/null
            done
            if (( okq )); then tune_raise net.core.rps_sock_flow_entries 32768; kv_set "$TUNE_DIR/nic.conf" "rps:$dev" "$mask"; fi
        fi
        if nic_qdisc_wanted && [[ -n "$(nic_qdisc_targets "$dev")" ]]; then if nic_set_qdisc "$dev"; then TUNE_OK=$((TUNE_OK + 1)); else TUNE_NO=$((TUNE_NO + 1)); fi; fi
        if command -v ethtool > /dev/null 2>&1; then
            while read -r feat f st; do
                nic_feature_fixed "$dev" "$feat" && continue
                cur=$(nic_feature "$dev" "$feat"); [[ -n "$cur" && "$cur" != "$st" ]] || continue
                kv_has "$TUNE_DIR/nic.orig" "off:$dev:$f" || kv_set "$TUNE_DIR/nic.orig" "off:$dev:$f" "$cur"
                if ethtool -K "$dev" "$f" "$st" > /dev/null 2>&1; then kv_set "$TUNE_DIR/nic.conf" "off:$dev:$f" "$st"; TUNE_OK=$((TUNE_OK + 1)); else TUNE_NO=$((TUNE_NO + 1)); fi
            done < <(nic_wanted_features)
        fi
        sq=$(softnet_stat | awk '{ print $2 }')
        [[ "$sq" =~ ^[0-9]+$ && "$sq" -gt 0 ]] && tune_raise net.core.netdev_budget 600
    fi
    if [[ "$mode" == 1 || "$mode" == only_rings ]] && command -v ethtool > /dev/null 2>&1; then
        local rmax tmax rcur tcur rn tn
        read -r rmax tmax rcur tcur <<< "$(nic_ring "$dev")"
        if (( rmax > rcur || tmax > tcur )); then
            rn=$(( rmax > rcur ? rmax : rcur )); tn=$(( tmax > tcur ? tmax : tcur ))        # a dimension the driver cannot raise keeps its value
            kv_has "$TUNE_DIR/nic.orig" "ring:$dev" || kv_set "$TUNE_DIR/nic.orig" "ring:$dev" "$rcur $tcur"
            if ethtool -G "$dev" rx "$rn" tx "$tn" > /dev/null 2>&1; then kv_set "$TUNE_DIR/nic.conf" "ring:$dev" "$rn $tn"; TUNE_OK=$((TUNE_OK + 1)); else TUNE_NO=$((TUNE_NO + 1)); fi
        fi
    fi
    return 0
}
nic_restore() {    # boot / heal: put the stored card settings back (only what is not already in place: a driver may blink the link on any set)
    [[ -s "$TUNE_DIR/nic.conf" ]] || return 0
    local k v kind dev what q rcur tcur
    while IFS='=' read -r k v; do
        kind="${k%%:*}"; dev="${k#*:}"; what="${dev#*:}"; dev="${dev%%:*}"
        [[ -d "$SYSFS_NET/$dev" ]] || continue
        case "$kind" in
            rps)  for q in "$SYSFS_NET/$dev"/queues/rx-*; do
                      [[ "$(nic_norm_mask "$(cat "$q/rps_cpus" 2> /dev/null)")" == "$(nic_norm_mask "$v")" ]] || echo "$v" > "$q/rps_cpus" 2> /dev/null
                  done ;;
            off)  command -v ethtool > /dev/null 2>&1 || continue
                  [[ "$(nic_feature "$dev" "$(nic_feat_name "$what")")" == "$v" ]] || ethtool -K "$dev" "$what" "$v" > /dev/null 2>&1 ;;
            ring) command -v ethtool > /dev/null 2>&1 || continue
                  read -r _ _ rcur tcur <<< "$(nic_ring "$dev")"
                  [[ "$rcur $tcur" == "$v" ]] || ethtool -G "$dev" rx "${v%% *}" tx "${v##* }" > /dev/null 2>&1 ;;
            qdisc) nic_set_qdisc "$dev" ;;
        esac
    done < "$TUNE_DIR/nic.conf"
    return 0
}
nic_feat_name() { case "$1" in gro) echo generic-receive-offload ;; gso) echo generic-segmentation-offload ;; tso) echo tcp-segmentation-offload ;; lro) echo large-receive-offload ;; *) echo "$1" ;; esac; }
nic_drift() {    # 0 = a stored card setting is gone again (link re-created, driver reloaded) and the card is back at its ORIGINAL value.
    local k v kind dev what live          # A value somebody else chose on purpose (neither ours nor the original) is not fought over.
    [[ -s "$TUNE_DIR/nic.conf" ]] || return 1
    while IFS='=' read -r k v; do
        kind="${k%%:*}"; dev="${k#*:}"; what="${dev#*:}"; dev="${dev%%:*}"
        [[ -d "$SYSFS_NET/$dev" ]] || continue
        case "$kind" in
            rps)  live=$(nic_norm_mask "$(cat "$SYSFS_NET/$dev/queues/rx-0/rps_cpus" 2> /dev/null)")
                  [[ "$live" == "$(nic_norm_mask "$v")" ]] && continue
                  [[ "$live" == "$(nic_norm_mask "$(kv_get "$TUNE_DIR/nic.orig" "rps:$dev:rx-0")")" ]] && return 0 ;;
            off)  command -v ethtool > /dev/null 2>&1 || continue
                  live=$(nic_feature "$dev" "$(nic_feat_name "$what")"); [[ -n "$live" && "$live" != "$v" ]] || continue
                  [[ "$live" == "$(kv_get "$TUNE_DIR/nic.orig" "off:$dev:$what")" ]] && return 0 ;;
            qdisc) [[ -n "$(nic_qdisc_targets "$dev")" ]] && return 0 ;;
        esac
    done < "$TUNE_DIR/nic.conf"
    return 1
}
nic_revert() {
    local k v kind dev what q n=0 qk qv t
    [[ -s "$TUNE_DIR/nic.orig" ]] && while IFS='=' read -r k v; do
        kind="${k%%:*}"; dev="${k#*:}"; what="${dev#*:}"; dev="${dev%%:*}"
        [[ -d "$SYSFS_NET/$dev" ]] || continue
        case "$kind" in
            rps)  q="$what"; { echo "$v" > "$SYSFS_NET/$dev/queues/$q/rps_cpus"; } 2> /dev/null && n=$((n + 1)) ;;
            rpsflow) q="$what"; { echo "$v" > "$SYSFS_NET/$dev/queues/$q/rps_flow_cnt"; } 2> /dev/null ;;
            off)  ethtool -K "$dev" "$what" "$v" > /dev/null 2>&1 && n=$((n + 1)) ;;
            ring) ethtool -G "$dev" rx "${v%% *}" tx "${v##* }" > /dev/null 2>&1 && n=$((n + 1)) ;;
            qdisc) read -r qk qv <<< "$v"; [[ -n "$qv" ]] || { qv="$qk"; qk=root; }           # "<root|mq> <qdisc>"; only a queue that still is OUR fq is put back
                   if [[ "$qk" == mq ]]; then
                       for t in $(tc qdisc show dev "$dev" 2> /dev/null | awk '$2 == "fq" { for (i = 1; i < NF; i++) if ($i == "parent") print $(i + 1) }'); do
                           tc qdisc replace dev "$dev" parent "$t" "$qv" 2> /dev/null && n=$((n + 1))
                       done
                   elif [[ "$(nic_root_qdisc "$dev")" == fq ]]; then tc qdisc replace dev "$dev" root "$qv" 2> /dev/null && n=$((n + 1)); fi ;;
        esac
    done < "$TUNE_DIR/nic.orig"
    : > "$TUNE_DIR/nic.orig"; : > "$TUNE_DIR/nic.conf"; echo "$n"
}
assist_nic() {
    local devs d plan="" info
    devs=$(for d in "$(nic_default_dev)" $(ls "$SYSFS_NET" 2> /dev/null); do nic_is_phys "$d" && echo "$d"; done | awk '!s[$0]++')
    [[ -n "$devs" ]] || devs=$(nic_default_dev)
    echo -e "\n  ${B}${W}Network card tuning${NC}\n"
    for d in $devs; do
        info=$(nic_scan "$d")
        echo -e "  ${W}$d${NC} ${GR}driver $(kvget "$info" driver), $(kvget "$info" speed) Mbit/s, MTU $(kvget "$info" mtu), $(kvget "$info" rxq) RX queue(s), $(nproc) CPU(s), RX drops $(kvget "$info" drops)${NC}"
        plan+=$(nic_plan "$d")$'\n'
    done
    plan=$(echo "$plan" | sed '/^$/d' | awk '!s[$0]++')
    echo ""
    if [[ -z "$plan" ]]; then echo -e "  ${G}Nothing to change: offloads are sane and the card already spreads its work.${NC}"
    else printf "   ${GR}%-30s %-14s    %s${NC}\n" "change" "now" "proposed"; echo "$plan"; echo ""
        echo -e "  ${GR}RPS lets every CPU core process packets of a single-queue card (typical VPS); LRO must be off on a forwarder.${NC}"
        confirm "Apply these changes?" y || return 1
        tune_count_reset
        for d in $devs; do nic_apply "$d"; done
        (( TUNE_OK > 0 )) && tune_hist nic "network card tuned ($(echo $devs))"
        tune_done
    fi
    local dd; for d in $devs; do dd=$(kvget "$(nic_scan "$d")" drops); if [[ "$dd" =~ ^[0-9]+$ ]] && (( dd > 0 )) && command -v ethtool > /dev/null 2>&1; then
        echo -e "\n  ${Y}$d has dropped $dd received packets since boot.${NC} ${GR}Larger ring buffers absorb bursts (may blink the link for a moment).${NC}"
        confirm "Maximise the ring buffers of $d?" n && { tune_count_reset; nic_apply "$d" only_rings; (( TUNE_OK > 0 )) && tune_hist nic "ring buffers of $d maximised"; tune_done; }
    fi; done
    return 0
}

# ── per-tunnel tuning ──
# Kernel settings are shared by every tunnel; what really is per tunnel is: the host route to its destination
# (congestion control, initial windows, quick ACKs, a pinned MTU), the engine's own options, and the TCP MSS of
# kernel-NAT-ed connections. A profile sets exactly those, transparently.
profile_info() {    # profile -> "label|what it is for"
    case "$1" in
        gaming)    echo "Gaming / calls|lowest ping and jitter: quick ACKs, short queues, fast failure detection" ;;
        bandwidth) echo "Max bandwidth|streaming, downloads, daily use: fast ramp-up, large windows" ;;
        multiuser) echo "Many users|lots of simultaneous connections: keeps resources in check, frees idle ones" ;;
        *)         echo "Balanced|good for mixed use (the default)" ;;
    esac
}
profile_route_attrs() {
    local bbr=""; [[ "$(sys_get net.ipv4.tcp_available_congestion_control)" == *bbr* ]] && bbr="congctl bbr"
    case "$1" in
        gaming)    echo "$bbr initcwnd 10 quickack 1" ;;
        bandwidth) echo "$bbr initcwnd 24 initrwnd 48" ;;
        multiuser) echo "$bbr" ;;
    esac
}
profile_realm_opts() {
    case "$1" in
        gaming)    printf 'tcp_timeout = 3\nudp_timeout = 120\ntcp_keepalive = 10\ntcp_keepalive_probe = 3\n' ;;
        bandwidth) printf 'tcp_timeout = 5\nudp_timeout = 60\n' ;;
        multiuser) printf 'tcp_timeout = 5\nudp_timeout = 30\ntcp_keepalive = 30\n' ;;
    esac
}
profile_realm_unit() {    # a raised priority is refused inside containers, so only on real hosts
    systemd-detect-virt -c -q 2> /dev/null && return 0
    case "$1" in gaming) echo "Nice=-10" ;; bandwidth) echo "Nice=-5" ;; esac
}
port_profile() { ( P_PROFILE=""; source "$PORTS_DIR/$1" 2> /dev/null; echo "${P_PROFILE:-}" ); }
port_get() {    # port_get <port> <P_KEY> -> its value, read without starting a process per line
    local k v
    { while IFS='=' read -r k v; do [[ "$k" == "$2" ]] && { v="${v#\"}"; echo "${v%\"}"; return 0; }; done < "$PORTS_DIR/$1"; } 2> /dev/null
    return 1
}
TUNE_CFG_RE='^P_(PROFILE|TUNE_MTU)="?[^" ]'      # a tunnel line that really carries a profile / pinned MTU
tune_any_config() { grep -qsE "$TUNE_CFG_RE" "$PORTS_DIR"/* 2> /dev/null; }
tune_port_table() {    # one line per tunnel, read in ONE pass over the port files: port|destination|method|profile|pinned MTU|blocked
    local f files=()     # (restore / sync ask for every tunnel; a process per file made that quadratic. Only regular files are handed to awk: a stray directory would stop it.)
    for f in "$PORTS_DIR"/*; do [[ -f "$f" ]] && files+=("$f"); done
    (( ${#files[@]} )) || return 0
    awk '
        function flush() { if (port != "") print port "|" d "|" m "|" p "|" t "|" b }
        FNR == 1 { flush(); port = FILENAME; sub(/^.*\//, "", port); d = ""; m = "iptables"; p = ""; t = ""; b = 0 }
        /^P_(DEST|METHOD|PROFILE|TUNE_MTU|BLOCKED)=/ {
            k = substr($0, 1, index($0, "=") - 1); v = substr($0, index($0, "=") + 1); gsub(/^"|"$/, "", v)
            if (k == "P_DEST") d = v; else if (k == "P_METHOD") m = v; else if (k == "P_PROFILE") p = v
            else if (k == "P_TUNE_MTU") t = v; else if (k == "P_BLOCKED") b = v
        }
        END { flush() }
    ' "${files[@]}" 2> /dev/null
}
tune_port_tuned() {    # does this tunnel carry a profile / pinned MTU? (read without starting a process)
    local l
    while IFS= read -r l; do [[ "$l" =~ $TUNE_CFG_RE ]] && return 0; done < "$PORTS_DIR/$1" 2> /dev/null
    return 1
}

tune_dest_ip() {    # destination of a tunnel as an IP. A name is looked up at most once a minute (cache in $TUNE_DIR/ipcache) and never for longer than 3 s:
    local h="$1" f ip t now      # restore / sync ask for every tunnel, and a slow resolver must not multiply
    valid_ip "$h" && { echo "$h"; return 0; }
    [[ -n "$h" ]] || return 0
    f="$TUNE_DIR/ipcache/${h//[^A-Za-z0-9._-]/_}"
    printf -v now '%(%s)T' -1 2> /dev/null; [[ "$now" =~ ^[0-9]{9,}$ ]] || now=$(date +%s)         # (bash older than 4.3 prints -1 for "now")
    if [[ -r "$f" ]]; then read -r t ip < "$f"; [[ "$t" =~ ^[0-9]+$ ]] && (( now - t < 60 )) && { echo "$ip"; return 0; }; fi
    ip=$(timeout 3 getent ahosts "$h" 2> /dev/null | awk '{ print $1; exit }')
    mkdir -p "$TUNE_DIR/ipcache" 2> /dev/null && echo "$now $ip" > "$f" 2> /dev/null
    echo "$ip"
}
tune_ip_forget() { [[ -n "$1" ]] && rm -f "$TUNE_DIR/ipcache/${1//[^A-Za-z0-9._-]/_}"; return 0; }       # an interactive action wants the answer of NOW (the lookup may have failed a moment ago)
tune_route_get() { local fam="-4"; is_ipv6 "$1" && fam="-6"; ip $fam -o route get "$1" 2> /dev/null | head -1; }
tune_route_set() {    # tune_route_set <ip> <attrs...> -> 0 ok · 1 a route that is not ours is in the way · 2 failed (undone)
    local ip="$1"; shift
    local fam="-4" plen=32 l dev via src mine other after
    is_ipv6 "$ip" && { fam="-6"; plen=128; }
    mine=$(ip $fam route show exact "$ip/$plen" proto "$PFM_ROUTE_PROTO" 2> /dev/null | head -1)
    other=$(ip $fam route show exact "$ip/$plen" 2> /dev/null | head -1)
    [[ -n "$other" && -z "$mine" ]] && return 1
    # our earlier route would answer the lookup below with its own, possibly stale, next hop: take it away first
    [[ -n "$mine" ]] && ip $fam route del "$ip/$plen" proto "$PFM_ROUTE_PROTO" 2> /dev/null
    l=$(tune_route_get "$ip"); [[ -n "$l" ]] || return 2
    [[ "$l" == local* || "$l" == broadcast* ]] && return 0          # an address of this very server: there is no path to tune
    dev=$(sed -n 's/.* dev \([^ ]*\).*/\1/p' <<< "$l"); via=$(sed -n 's/.* via \([^ ]*\).*/\1/p' <<< "$l"); src=$(sed -n 's/.* src \([^ ]*\).*/\1/p' <<< "$l")
    ip $fam route replace "$ip/$plen" ${via:+via "$via"} dev "$dev" ${src:+src "$src"} proto "$PFM_ROUTE_PROTO" "$@" 2> /dev/null || return 2
    after=$(tune_route_get "$ip")
    if [[ "$(sed -n 's/.* dev \([^ ]*\).*/\1/p' <<< "$after")" != "$dev" || "$(sed -n 's/.* via \([^ ]*\).*/\1/p' <<< "$after")" != "$via" ]]; then
        ip $fam route del "$ip/$plen" proto "$PFM_ROUTE_PROTO" 2> /dev/null; return 2
    fi
    return 0
}
tune_route_del() { local fam="-4" plen=32; is_ipv6 "$1" && { fam="-6"; plen=128; }; ip $fam route del "$1/$plen" proto "$PFM_ROUTE_PROTO" 2> /dev/null; return 0; }

tune_dest_attrs() {    # tune_dest_attrs <ip> [port to ignore] -> attributes for the host route to <ip>, merged over all tunnels that use it
    local ip="$1" skip="${2:-}" port d m prof pmtu best="" rank bestrank=0 mtu="" ri kind devmtu attrs
    while IFS='|' read -r port d m prof pmtu _; do
        [[ -n "$port" && "$port" != "$skip" && -n "$prof$pmtu" ]] || continue       # an untuned tunnel adds nothing - and is not even resolved
        if valid_ip "$d"; then [[ "$d" == "$ip" ]] || continue                       # an address needs no process; only a name is looked up
        else [[ "$(tune_dest_ip "$d")" == "$ip" ]] || continue; fi
        if [[ "$m" != iptables ]]; then
            case "$prof" in gaming) rank=4 ;; bandwidth) rank=3 ;; multiuser) rank=2 ;; *) rank=0 ;; esac
            (( rank > bestrank )) && { bestrank=$rank; best="$prof"; }
        fi
        [[ "$pmtu" =~ ^[0-9]+$ ]] && { [[ -z "$mtu" ]] || (( pmtu < mtu )) && mtu="$pmtu"; }
    done < <(tune_port_table)
    attrs=$(profile_route_attrs "$best")
    if [[ -n "$mtu" ]]; then       # pin the MTU on the route only where lowering the device would hurt other traffic
        ri=$(probe_route "$ip"); kind=$(kvget "$ri" kind); devmtu=$(kvget "$ri" devmtu)
        [[ ! "$kind" =~ ^(gre|gretap|ipip|sit|wireguard|vxlan|ip6gre|ip6gretap|ip6tnl|geneve)$ && "$devmtu" =~ ^[0-9]+$ ]] && (( mtu < devmtu )) && attrs="$attrs mtu lock $mtu"
    fi
    echo $attrs
}
TUNE_ROUTE_RC=0     # result of the last route change: 1 = a route that is not ours is in the way, 2 = refused
tune_apply_dest() {    # tune_apply_dest <ip> [port to ignore]
    local attrs; attrs=$(tune_dest_attrs "$1" "${2:-}")
    if [[ -n "$attrs" ]]; then tune_route_set "$1" $attrs; TUNE_ROUTE_RC=$?; else tune_route_del "$1"; TUNE_ROUTE_RC=0; fi
    return 0
}
tune_route_note() {    # tells why the route part of a change could not be applied (the rest of it was)
    case "$TUNE_ROUTE_RC" in
        1) echo -e "  ${Y}Note: a route to this destination already exists that PFM did not create (a VPN / provider / your own setup),${NC}"
           echo -e "  ${Y}so PFM leaves it alone: the route settings (congestion control, initial window, pinned MTU) were NOT applied.${NC}" ;;
        2) echo -e "  ${Y}Note: the kernel refused the route settings (container or restricted host); the other parts were applied.${NC}" ;;
    esac
}
tune_mss_listed() { local l; while read -r l; do [[ "$l" == "$1" ]] && return 0; done < "$TUNE_DIR/mss.ports" 2> /dev/null; return 1; }
tune_mss_mark() {    # tune_mss_mark add|del <port>: mss.ports lists the tunnels that have MSS rules, so the others never pay for a look at the firewall
    local t
    if [[ "$1" == add ]]; then tune_mss_listed "$2" || echo "$2" >> "$TUNE_DIR/mss.ports"
    else t=$(mktemp "$TUNE_DIR/mss.XXXXXX") && { grep -vx "$2" "$TUNE_DIR/mss.ports" > "$t" 2> /dev/null; mv -f "$t" "$TUNE_DIR/mss.ports"; }; fi
    return 0
}
tune_mss_remove() {
    local c
    [[ -d "$TUNE_DIR" ]] || return 0                                                  # the assistant was never used here
    [[ -f "$TUNE_DIR/mss.ports" ]] && ! tune_mss_listed "$1" && return 0         # this tunnel never had any
    for c in iptables ip6tables; do ipt_del_tag "$c" mangle FORWARD "pfm_mss_$1"; done
    tune_mss_mark del "$1"
}
tune_mss_apply() {    # kernel-NAT-ed connections only: realm/HAProxy open their own connections and take the MSS from the route
    local port="$1"; [[ -f "$PORTS_DIR/$port" ]] || return 0
    local P_DEST="" P_DPORT="$port" P_METHOD="iptables" P_TUNE_MTU=""; source "$PORTS_DIR/$port"
    tune_mss_remove "$port"
    [[ "$P_METHOD" == iptables && "$P_TUNE_MTU" =~ ^[0-9]+$ ]] || return 0
    local cmd mss; cmd=$(ipt "$P_DEST"); mss=$(( P_TUNE_MTU - 40 )); is_ipv6 "$P_DEST" && mss=$(( P_TUNE_MTU - 60 ))
    tune_init; tune_mss_mark add "$port"        # listed before the rules exist: a half-done change is still cleaned up
    # "set-mss" never raises an MSS that is already lower; both directions, because the SYN-ACK leaves through the other interface
    $cmd -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -d "$P_DEST" --dport "$P_DPORT" -m comment --comment "pfm_mss_${port}" -j TCPMSS --set-mss "$mss" 2> /dev/null
    $cmd -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -s "$P_DEST" --sport "$P_DPORT" -m comment --comment "pfm_mss_${port}" -j TCPMSS --set-mss "$mss" 2> /dev/null
    return 0
}
tune_apply_tunnel() {    # tune_apply_tunnel <port> [force]: route attributes + MSS from the stored profile / MTU. Called whenever a tunnel's rules are (re)applied,
    local port="$1" force="${2:-}" P_DEST="" ip      # so it costs next to nothing on a server whose tunnels were never tuned ("force": the caller just changed or cleared them)
    [[ -f "$PORTS_DIR/$port" ]] || return 0
    [[ -n "$force" ]] || tune_any_config || [[ -s "$TUNE_DIR/mss.ports" ]] || return 0
    [[ -n "$force" ]] || tune_port_tuned "$port" || tune_mss_listed "$port" || return 0      # an untuned tunnel needs nothing (and its name is not looked up): the route follows the TUNED ones
    P_DEST=$(port_get "$port" P_DEST)
    ip=$(tune_dest_ip "$P_DEST"); [[ -n "$ip" ]] || return 0
    tune_apply_dest "$ip"; tune_mss_apply "$port"
    return 0
}
tune_remove_tunnel() {    # a tunnel is being removed: its MSS rules go, the route is recomputed without it
    local port="$1" P_DEST ip
    tune_mss_remove "$port"
    tune_any_config || return 0         # nothing is tuned anywhere, so there is no route of ours to recompute
    P_DEST=$(port_get "$port" P_DEST); ip=$(tune_dest_ip "$P_DEST")
    [[ -n "$ip" ]] && tune_apply_dest "$ip" "$port"
    return 0
}

assist_profile_set() {    # assist_profile_set <port> <profile>
    local port="$1" prof="$2" lbl what
    case "$prof" in gaming|bandwidth|balanced|multiuser) ;; *) echo -e "  ${R}Unknown profile '${prof}' - use gaming, bandwidth, balanced or multiuser.${NC}"; return 1 ;; esac
    valid_port "$port" && [[ -f "$PORTS_DIR/$port" ]] || { echo -e "  ${R}There is no tunnel on port '${port}'.${NC}"; return 1; }
    local P_DEST="" P_DPORT="$port" P_METHOD="iptables" P_PROFILE="" P_BLOCKED=0; source "$PORTS_DIR/$port"
    IFS='|' read -r lbl what <<< "$(profile_info "$prof")"
    echo -e "\n  ${B}${W}Tune :$port → ${P_DEST}:${P_DPORT} [$P_METHOD]${NC}   ${C}$lbl${NC}\n  ${GR}$what${NC}\n"
    if [[ "$P_METHOD" == iptables ]]; then
        echo -e "  ${Y}Profiles need the realm or HAProxy engine.${NC}"
        echo -e "  ${GR}Kernel NAT (iptables) forwards packets without ever terminating the connection, so the only per-tunnel setting it has is the TCP MSS ('MTU auto-tune').${NC}"
        echo -e "  ${GR}Server-wide settings - BBR, buffers, network card - are the other items of the Optimization Assistant.${NC}"
        return 1
    fi
    echo -e "  ${GR}What changes for this tunnel:${NC}"
    case "$P_METHOD" in
        realm)   echo -e "   • route to ${P_DEST}: $(profile_route_attrs "$prof" | sed 's/^$/(default)/')"
                 echo -e "   • realm options: $(profile_realm_opts "$prof" | tr '\n' ';' | sed 's/;$//;s/ = /=/g' | sed 's/^$/(defaults)/')"
                 echo -e "   • service priority: $(profile_realm_unit "$prof" | sed 's/^$/(unchanged)/')"
                 echo -e "   ${Y}• the realm service restarts (connections of this tunnel reconnect)${NC}" ;;
        haproxy) echo -e "   • route to ${P_DEST}: $(profile_route_attrs "$prof" | sed 's/^$/(default)/')"
                 echo -e "   • HAProxy keep-alive / timeouts / limits for this tunnel (graceful reload)" ;;
    esac
    [[ "$P_BLOCKED" == 1 ]] && echo -e "   ${Y}• this tunnel is blocked right now: the profile is only stored; it takes effect after the tunnel is unblocked and 'pfm restore' has run${NC}"
    local curp; curp=$(port_profile "$port"); [[ "${curp:-balanced}" != "$prof" ]] || { echo -e "\n  ${G}This profile is already active.${NC}"; return 0; }
    confirm "Apply profile '$lbl'?" y || return 1
    if [[ "$prof" == balanced ]]; then port_unset "$port" P_PROFILE; else port_set "$port" P_PROFILE "$prof"; fi
    if [[ "$P_BLOCKED" == 1 ]]; then       # starting a blocked tunnel's engine would open it again: store only
        tune_hist profile ":$port -> $lbl (stored; tunnel is blocked)"
        echo -e "  ${G}Stored.${NC} ${GR}It takes effect after the tunnel is unblocked and 'pfm restore' (or a reboot) has run.${NC}"; return 0
    fi
    local up=1
    case "$P_METHOD" in
        realm)   create_realm_service "$port" "$P_DEST" "$P_DPORT" 0; start_realm_service "$port"; wait_engine "$port" realm 6 || up=0 ;;
        haproxy) rebuild_haproxy_cfg > /dev/null 2>&1; engine_listening "$port" haproxy || up=0 ;;
    esac
    if (( ! up )); then     # an option the installed realm / HAProxy version does not know must never leave a tunnel dead
        echo -e "  ${R}$P_METHOD did not come back with this profile (an option may not be supported by the installed version) - restoring the previous settings.${NC}"
        if [[ -n "$curp" ]]; then port_set "$port" P_PROFILE "$curp"; else port_unset "$port" P_PROFILE; fi
        case "$P_METHOD" in
            realm)   create_realm_service "$port" "$P_DEST" "$P_DPORT" 0; start_realm_service "$port"; wait_engine "$port" realm 6 ;;
            haproxy) rebuild_haproxy_cfg > /dev/null 2>&1 ;;
        esac
        tune_apply_tunnel "$port" force
        return 1
    fi
    tune_apply_tunnel "$port" force
    tune_hist profile ":$port -> $lbl"
    echo -e "  ${G}Profile applied.${NC} ${GR}Run the Bench Test to measure the effect.${NC}"
    tune_route_note
}

# ── MTU auto-tune ──
tunnel_kind_is_tunnel() { [[ "$1" =~ ^(gre|gretap|ipip|sit|wireguard|vxlan|ip6gre|ip6gretap|ip6tnl|geneve)$ ]]; }
assist_mtu() {    # assist_mtu <port>
    local port="$1" ip ri dev kind devmtu ovh remote inner pm bh target umtu upath cap note="" floor=576 had=0 fam="-4" plen=32
    valid_port "$port" && [[ -f "$PORTS_DIR/$port" ]] || { echo -e "  ${R}There is no tunnel on port '${port}'.${NC}"; return 1; }
    local P_DEST="" P_METHOD="iptables" P_TUNE_MTU=""; source "$PORTS_DIR/$port"
    tune_ip_forget "$P_DEST"; ip=$(tune_dest_ip "$P_DEST"); [[ -n "$ip" ]] || { echo -e "  ${R}Destination does not resolve.${NC}"; return 1; }
    is_ipv6 "$ip" && { floor=1280; fam="-6"; plen=128; }
    ensure_tool ping "MTU test" || { echo -e "  ${R}ping is required.${NC}"; return 1; }
    ri=$(probe_route "$ip"); dev=$(kvget "$ri" dev); kind=$(kvget "$ri" kind); devmtu=$(kvget "$ri" devmtu); ovh=$(kvget "$ri" overhead); remote=$(kvget "$ri" remote)
    [[ "$devmtu" =~ ^[0-9]+$ ]] && (( devmtu > 0 )) || { echo -e "  ${R}No route to $ip.${NC}"; return 1; }
    echo -e "\n  ${B}${W}MTU auto-tune${NC}  ${GR}:$port → $ip  via $dev ($kind, MTU $devmtu)${NC}\n"
    echo -ne "  ${GR}Measuring the path with DF-bit probes...${NC}"
    # a pin made by an earlier run would cap the probes themselves: measure without it, put it back right after
    [[ -n "$(ip $fam route show exact "$ip/$plen" proto "$PFM_ROUTE_PROTO" 2> /dev/null)" ]] && { had=1; tune_route_del "$ip"; }
    inner=$(probe_mtu "$ip" "$devmtu"); (( had )) && tune_apply_dest "$ip"
    pm=$(kvget "$inner" pmtu); bh=$(kvget "$inner" blackhole)
    if [[ "$(kvget "$inner" icmp)" == blocked ]]; then echo -e "\r  ${Y}ICMP is filtered towards $ip - the MTU cannot be measured reliably.${NC}                "; return 1; fi
    if [[ "$(kvget "$inner" unreliable)" == 1 ]]; then
        echo -e "\r  ${Y}The measurement is not reliable: replies were lost or rate-limited, the path seemed to carry only $pm bytes (no real network is that small).${NC}"
        echo -e "  ${GR}Nothing was changed. Try again in a minute.${NC}"; return 1
    fi
    echo -e "\r  Path to the destination ......... ${W}$pm${NC} bytes   ${GR}(interface $devmtu, black hole: $([[ "$bh" == 1 ]] && echo YES || echo no))${NC}        "
    target=$devmtu
    [[ "$pm" =~ ^[0-9]+$ ]] && (( pm < target )) && target=$pm
    if tunnel_kind_is_tunnel "$kind" && [[ "$remote" != "-" && -n "$remote" ]]; then
        local ur udev
        ur=$(probe_route "$remote"); udev=$(kvget "$ur" devmtu)
        if [[ "$udev" =~ ^[0-9]+$ ]]; then
            echo -ne "  ${GR}Measuring the underlay path to the tunnel endpoint $remote ...${NC}"
            umtu=$(probe_mtu "$remote" "$udev"); upath=$(kvget "$umtu" pmtu)
            if [[ "$upath" =~ ^[0-9]+$ && "$(kvget "$umtu" unreliable)" != 1 ]]; then
                cap=$(( upath - ovh ))
                echo -e "\r  Underlay to $remote ... ${W}$upath${NC} bytes - $kind overhead $ovh = ${W}$cap${NC} for the tunnel        "
                (( cap < target )) && target=$cap
                (( cap > devmtu )) && note="The tunnel could carry up to $cap bytes (+$(( (cap - devmtu) * 100 / devmtu ))%), but both ends must be changed together - not done automatically."
            else echo -e "\r  ${GR}Underlay path not measurable (ICMP filtered or unreliable at $remote).${NC}                "; fi
        fi
    fi
    echo -e "\n  Recommended inner MTU ........... ${B}${C}$target${NC}   ${GR}(now $devmtu)${NC}"
    [[ -n "$note" ]] && echo -e "  ${GR}$note${NC}"
    if (( target < floor )) || { tunnel_kind_is_tunnel "$kind" && (( target < 1280 )) && (( target < devmtu )); }; then
        echo -e "\n  ${Y}$target bytes is below what IPv4/IPv6 need ($(tunnel_kind_is_tunnel "$kind" && echo 1280 || echo "$floor")): a tunnel interface that small drops IPv6.${NC} ${GR}Nothing was changed - check the underlay by hand.${NC}"
        return 1
    fi
    if [[ "$P_TUNE_MTU" == "$target" ]] && ! tunnel_kind_is_tunnel "$kind"; then
        echo -e "\n  ${G}This MTU is already pinned for the tunnel and still matches the path.${NC}"; return 0
    fi
    if (( target >= devmtu )) && [[ "$bh" != 1 ]]; then
        echo -e "\n  ${G}The MTU is already right for this path.${NC}"
        if [[ -n "$P_TUNE_MTU" ]]; then
            echo -e "  ${GR}A pinned value of $P_TUNE_MTU from an earlier run is still in place, but the path carries the full $devmtu now.${NC}"
            if confirm "Remove that pin?" y; then
                port_unset "$port" P_TUNE_MTU; tune_apply_tunnel "$port" force
                tune_hist mtu ":$port pinned MTU $P_TUNE_MTU removed (the path carries $devmtu)"; echo -e "  ${G}Removed.${NC}"
            fi
        fi
        return 0
    fi
    echo ""
    if tunnel_kind_is_tunnel "$kind"; then
        echo -e "  ${GR}Plan: set $dev MTU to $target (persistent)$([[ "$P_METHOD" == iptables ]] && echo ", clamp the TCP MSS of this tunnel to $(( target - 40 ))").${NC}"
        echo -e "  ${GR}Set the same MTU on the other end of the tunnel for the best result.${NC}"
    else
        echo -e "  ${GR}Plan: pin MTU $target on the route to $ip only (other traffic keeps $devmtu)$([[ "$P_METHOD" == iptables ]] && echo ", clamp the TCP MSS of this tunnel to $(( target - 40 ))").${NC}"
    fi
    confirm "Apply?" y || return 1
    if tunnel_kind_is_tunnel "$kind"; then save_mtu "$dev" "$target"; kv_set "$TUNE_DIR/mtu.devs" "$dev" 1; fi
    port_set "$port" P_TUNE_MTU "$target"
    tune_apply_tunnel "$port" force
    tune_hist mtu ":$port path MTU $pm -> pinned $target on $dev"
    if tune_needs_heal "$port"; then       # stored, but the system would not take the route pin / the MSS rule: do not claim more than that
        echo -e "  ${Y}The MTU ($target) is stored, but the route pin / MSS rule could not be installed on this system.${NC} ${GR}It is retried every 30 minutes; 'pfm doctor' shows more.${NC}"
    else
        inner=$(probe_mtu "$ip" "$target")
        echo -e "  ${G}Applied.${NC} ${GR}Check: $(kvget "$inner" pmtu) bytes cross the path now. Run the Bench Test to measure the effect.${NC}"
    fi
    tune_route_note
}
assist_mss() {    # assist_mss <port>
    local port="$1" P_DEST="" P_METHOD="iptables" P_TUNE_MTU="" ri ip mtu
    [[ -f "$PORTS_DIR/$port" ]] || return 1; source "$PORTS_DIR/$port"
    echo -e "\n  ${B}${W}TCP MSS clamp${NC}  ${GR}:$port${NC}\n"
    if [[ "$P_METHOD" != iptables ]]; then
        echo -e "  ${GR}Not needed: $P_METHOD opens its own connections, so the kernel already uses the route MTU for the MSS.${NC}"
        echo -e "  ${GR}Use 'MTU auto-tune' if the path MTU is the problem.${NC}"; return 0
    fi
    ip=$(tune_dest_ip "$P_DEST"); ri=$(probe_route "$ip"); mtu="${P_TUNE_MTU:-$(kvget "$ri" devmtu)}"
    [[ "$mtu" =~ ^[0-9]+$ ]] || return 1
    echo -e "  ${GR}Kernel-NAT-ed connections are not terminated here, so nobody lowers their MSS if the path is smaller than 1500;${NC}"
    echo -e "  ${GR}big packets then vanish (PMTU black hole). Clamping the SYN's MSS to $(( mtu - 40 )) (MTU $mtu) prevents that.${NC}\n"
    confirm "Clamp the MSS of :$port to $(( mtu - 40 ))?" y || return 1
    port_set "$port" P_TUNE_MTU "$mtu"; tune_apply_tunnel "$port" force
    tune_hist mss ":$port TCP MSS clamped to $(( mtu - 40 ))"
    if tune_needs_heal "$port"; then echo -e "  ${Y}Stored, but the MSS rule could not be installed on this system.${NC} ${GR}It is retried every 30 minutes; 'pfm doctor' shows more.${NC}"
    else echo -e "  ${G}Done.${NC}"; fi
}

assist_label() {
    case "$1" in
        bbr) echo "Enable BBR + fq" ;; buffers) echo "Size TCP buffers" ;; mtu) echo "MTU auto-tune" ;; mss) echo "Clamp TCP MSS" ;;
        nic) echo "Network card tuning" ;; conntrack) echo "Raise connection limits" ;; dns) echo "DNS benchmark" ;;
        engine) echo "Try another engine" ;;
        profile:gaming) echo "Gaming profile" ;; profile:bandwidth) echo "Max-bandwidth profile" ;;
        profile:multiuser) echo "Many-users profile" ;; profile:balanced) echo "Balanced profile" ;;
        *) echo "$1" ;;
    esac
}
assist_do() {    # assist_do <action id> [port] - one entry point for the Bench Test's "next steps"
    local id="$1" port="${2:-}" rtt
    case "$id" in
        bbr) assist_bbr ;;
        buffers) rtt=$(bget p_avg); [[ -z "$rtt" || "$rtt" == 0 ]] && rtt=$(bget ci_krtt); assist_buffers "$(fmt0 "${rtt:-150}")" 1000 ;;
        mtu) assist_mtu "$port" ;;
        mss) assist_mss "$port" ;;
        nic) assist_nic ;;
        conntrack) assist_limits ;;
        dns) assist_dns ;;
        engine) echo -e "\n  ${GR}Change the engine from the main menu: delete the tunnel and add it again with the other engine${NC}"
                echo -e "  ${GR}(iptables = kernel NAT, no userspace copy; realm / HAProxy = per-tunnel tuning and BBR).${NC}" ;;
        profile:*) assist_profile_set "$port" "${id#profile:}" ;;
        *) echo -e "  ${R}Unknown action: $id${NC}" ;;
    esac
}

# ── DNS: measure the resolvers, refuse liars, keep the fastest honest one ──
dns_candidates() {
    if [[ -n "${PFM_DNS_CANDIDATES:-}" ]]; then printf '%s\n' "$PFM_DNS_CANDIDATES"; return; fi
    printf '%s\n' "Cloudflare|1.1.1.1 1.0.0.1" "Google|8.8.8.8 8.8.4.4" "Quad9|9.9.9.9 149.112.112.112" \
                  "OpenDNS|208.67.222.222 208.67.220.220" "AdGuard|94.140.14.14 94.140.15.15" "CleanBrowsing|185.228.168.9 185.228.169.9"
}
dns_system_resolvers() {
    { awk '/^nameserver/ { print $2 }' "$RESOLV_CONF" 2> /dev/null
      command -v resolvectl > /dev/null 2>&1 && resolvectl dns 2> /dev/null | sed 's/^[^:]*://' | tr ' ' '\n'
    } | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | awk '!s[$0]++'
}
dns_bogon() {    # private / reserved address in an answer for a public name = a rewritten answer
    local a b c d; IFS=. read -r a b c d <<< "$1"
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] || return 1
    (( a == 0 || a == 10 || a == 127 || a >= 224 )) && return 0
    (( a == 169 && b == 254 )) && return 0
    (( a == 172 && b >= 16 && b <= 31 )) && return 0
    (( a == 192 && b == 168 )) && return 0
    (( a == 100 && b >= 64 && b <= 127 )) && return 0
    return 1
}
dns_query() {    # dns_query <ip[#port]> <name> [A|AAAA] -> "<STATUS> <ms> <addresses>"
    local spec="$1" name="$2" type="${3:-A}" ip="${1%%#*}" port=53 out st ms ips
    [[ "$spec" == *#* ]] && port="${spec##*#}"
    out=$(dig +tries=1 +time=2 +noall +comments +answer +stats -p "$port" @"$ip" "$name" "$type" 2>&1)
    st=$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<< "$out" | head -1)
    [[ -n "$st" ]] || { echo "TIMEOUT -1"; return 1; }
    ms=$(sed -n 's/.*Query time: \([0-9]*\) msec.*/\1/p' <<< "$out" | head -1)
    ips=$(awk -v t="$type" '$4 == t { print $5 }' <<< "$out" | tr '\n' ',')
    echo "$st ${ms:-0} ${ips%,}"
}
med() { awk '{ for (i = 1; i <= NF; i++) v[++n] = $i } END { if (n == 0) { print -1; exit } for (i = 2; i <= n; i++) { t = v[i]; for (j = i - 1; j >= 1 && v[j] > t; j--) v[j+1] = v[j]; v[j+1] = t } print v[int((n + 1) / 2)] }' <<< "$1"; }
dns_bench_one() {    # dns_bench_one <spec> <domains...> ("!name" = a name a tunnel needs - it must resolve) -> spec|ok|total|warm ms|fresh ms|bogus|nxdomain-rewrites|alive|required failures
    local spec="$1"; shift
    local d r st ms ips st6 ms6 ips6 i ok=0 tot=0 bogus=0 nx=0 warm="" cold="" n=0 name req rfail=0
    r=$(dns_query "$spec" "${1#!}")
    [[ "${r%% *}" == TIMEOUT ]] && { echo "$spec|0|0|-1|-1|0|0|0|0"; return 0; }
    for d in "$@"; do
        req=0; [[ "$d" == '!'* ]] && { req=1; d="${d#!}"; }
        tot=$((tot + 1)); dns_query "$spec" "$d" > /dev/null; r=$(dns_query "$spec" "$d")     # the second answer comes from the resolver's cache
        read -r st ms ips <<< "$r"
        if [[ "$st" == NOERROR && -n "$ips" ]]; then
            ok=$((ok + 1)); warm+=" $ms"
            # a tunnel's own name may point to a private address on purpose; only public names are judged by that
            (( req )) || for i in ${ips//,/ }; do dns_bogon "$i" && bogus=$((bogus + 1)); done
        elif (( req )); then          # a name a tunnel needs may be IPv6-only: an AAAA answer counts as resolved too
            read -r st6 ms6 ips6 <<< "$(dns_query "$spec" "$d" AAAA)"
            if [[ "$st6" == NOERROR && -n "$ips6" ]]; then (( ok += 1 )); warm+=" $ms6"; else (( rfail += 1 )); fi
        fi
    done
    for d in "$@"; do    # a name that cannot exist forces a real lookup; a resolver that "finds" it rewrites NXDOMAIN
        [[ "$d" == '!'* ]] && continue
        (( n >= 3 )) && break; n=$((n + 1)); name="pfmx${RANDOM}${RANDOM}.$d"
        read -r st ms ips <<< "$(dns_query "$spec" "$name")"
        case "$st" in NXDOMAIN) cold+=" $ms" ;; NOERROR) [[ -n "$ips" ]] && nx=$((nx + 1)) ;; esac
    done
    echo "$spec|$ok|$tot|$(med "$warm")|$(med "$cold")|$bogus|$nx|1|$rfail"
}
RESOLVED_DIR="${PFM_RESOLVED_DIR:-/etc/systemd/resolved.conf.d}"        # drop-in directories (tests point these at a scratch tree)
RESOLVED_RUN="${PFM_RESOLVED_RUN:-/run/systemd/resolve}"
NM_DIR="${PFM_NM_DIR:-/etc/NetworkManager/conf.d}"
dns_mode() {    # resolved / nm / classic = we can change it · symlink / managed = another tool owns resolv.conf: we only say what to set
    if systemctl is-active --quiet systemd-resolved > /dev/null 2>&1 && [[ "$(readlink -f "$RESOLV_CONF" 2> /dev/null)" == "$RESOLVED_RUN"/* ]]; then echo resolved
    elif grep -qi networkmanager "$RESOLV_CONF" 2> /dev/null; then
        # plain NetworkManager lists real nameservers; a local stub (dnsmasq / resolved plugin) or a symlink means a setup we must not reshape
        if systemctl is-active --quiet NetworkManager > /dev/null 2>&1 && [[ ! -L "$RESOLV_CONF" ]] && ! grep -q '^nameserver 127\.' "$RESOLV_CONF" 2> /dev/null; then echo nm; else echo managed; fi
    elif [[ -L "$RESOLV_CONF" ]]; then echo symlink
    else echo classic; fi
}
dns_current_line() {    # every nameserver in use, a local stub (127.x) included: it is what this machine really asks
    { awk '/^nameserver/ { print $2 }' "$RESOLV_CONF" 2> /dev/null
      command -v resolvectl > /dev/null 2>&1 && resolvectl dns 2> /dev/null | sed 's/^[^:]*://' | tr ' ' '\n'
    } | grep -E '^[0-9A-Fa-f:.]+$' | awk '!s[$0]++' | tr '\n' ' '
}
dns_write_file() { { cat "$2" > "$1"; } 2> /dev/null && cmp -s "$2" "$1"; }          # dns_write_file <target> <content file>: written AND read back
dns_apply() {    # dns_apply <ip1> [ip2 ...]
    local mode backup="$TUNE_DIR/dns.orig" servers="$*" t ip keep="" fresh=0
    mode=$(dns_mode); tune_init
    case "$mode" in symlink|managed) echo -e "  ${Y}$RESOLV_CONF is managed by another tool (a symlink / NetworkManager plugin / resolvconf). Set these resolvers there instead: ${servers}${NC}"; return 1 ;; esac
    if [[ ! -s "$TUNE_DIR/dns.conf" ]]; then        # nothing of ours is active: this is the moment to remember the original (an older backup would be stale)
        rm -rf "$backup"; mkdir -p "$backup"; fresh=1
        echo "$mode" > "$backup/mode"; [[ -f "$RESOLV_CONF" ]] && cp -P "$RESOLV_CONF" "$backup/resolv.conf" 2> /dev/null
    fi
    case "$mode" in           # (a failure below removes the backup it just made: a copy of a file that was never changed must never be "restored" later)
        resolved)
            mkdir -p "$RESOLVED_DIR"
            printf '[Resolve]\nDNS=%s\nFallbackDNS=8.8.8.8 9.9.9.9\nDomains=~.\n' "$servers" > "$RESOLVED_DIR/90-pfm-dns.conf"
            systemctl restart systemd-resolved 2> /dev/null ;;       # (whether names still resolve is checked by the caller, which rolls back)
        nm)
            mkdir -p "$NM_DIR"
            printf '[global-dns-domain-*]\nservers=%s\n' "${servers// /,}" > "$NM_DIR/90-pfm-dns.conf"
            systemctl reload NetworkManager 2> /dev/null || { rm -f "$NM_DIR/90-pfm-dns.conf"; (( fresh )) && rm -rf "$backup"; echo -e "  ${R}NetworkManager did not accept the change.${NC}"; return 1; } ;;
        classic)
            # our resolvers first, then the ORIGINAL first resolver as a fallback (a private / DHCP resolver that still answers when ours is unreachable), then search/options lines
            for ip in $(awk '/^nameserver/ { print $2 }' "$backup/resolv.conf" 2> /dev/null); do [[ " $servers " == *" $ip "* ]] || { keep="$ip"; break; }; done
            t=$(mktemp) || { (( fresh )) && rm -rf "$backup"; return 1; }
            { for ip in $servers; do echo "nameserver $ip"; done; [[ -n "$keep" ]] && echo "nameserver $keep"; grep -v '^nameserver' "$RESOLV_CONF" 2> /dev/null; } > "$t"
            if ! dns_write_file "$RESOLV_CONF" "$t"; then
                echo -e "  ${R}Could not write $RESOLV_CONF - putting the old content back.${NC}"
                [[ -f "$backup/resolv.conf" ]] && { cat "$backup/resolv.conf" > "$RESOLV_CONF"; } 2> /dev/null
                rm -f "$t"; (( fresh )) && rm -rf "$backup"; return 1
            fi
            rm -f "$t" ;;
    esac
    kv_set "$TUNE_DIR/dns.conf" servers "$servers"; kv_set "$TUNE_DIR/dns.conf" mode "$mode"
    return 0
}
dns_revert() {    # puts back what is actually in effect (not what was planned); prints how many things were restored
    local backup="$TUNE_DIR/dns.orig" mode n=0 keep=0
    # nothing of ours is active: a backup that is lying around is stale and is never restored over what the admin has now
    if [[ ! -s "$TUNE_DIR/dns.conf" ]]; then [[ -d "$backup" ]] && rm -rf "$backup"; echo 0; return 0; fi
    mode=$(kv_get "$TUNE_DIR/dns.conf" mode); [[ -n "$mode" ]] || mode=$(cat "$backup/mode" 2> /dev/null)
    if [[ -f "$RESOLVED_DIR/90-pfm-dns.conf" ]]; then rm -f "$RESOLVED_DIR/90-pfm-dns.conf"; systemctl restart systemd-resolved 2> /dev/null; n=$((n + 1)); fi
    if [[ -f "$NM_DIR/90-pfm-dns.conf" ]]; then rm -f "$NM_DIR/90-pfm-dns.conf"; systemctl reload NetworkManager 2> /dev/null; n=$((n + 1)); fi
    if [[ "$mode" == classic && -f "$backup/resolv.conf" ]]; then
        if [[ -L "$RESOLV_CONF" ]]; then log "dns revert: $RESOLV_CONF is a symlink now (another tool took it over) - left alone"
        elif dns_write_file "$RESOLV_CONF" "$backup/resolv.conf"; then n=$((n + 1))
        else keep=1; log "dns revert: $RESOLV_CONF could not be written - the saved original stays in $backup"; fi          # the only copy of the original is not thrown away
    fi
    (( keep )) || { rm -rf "$backup"; rm -f "$TUNE_DIR/dns.conf"; }
    echo "$n"
}
dns_heal() {    # a DHCP client or cloud-init may rewrite a plain resolv.conf: put ours back (never over a file another tool owns, never when our resolver stopped answering)
    [[ -s "$TUNE_DIR/dns.conf" ]] || return 0
    [[ "$(kv_get "$TUNE_DIR/dns.conf" mode)" == classic ]] || return 0
    local want first r; want=$(kv_get "$TUNE_DIR/dns.conf" servers); first=$(awk '/^nameserver/ { print $2; exit }' "$RESOLV_CONF" 2> /dev/null)
    [[ "$first" == "${want%% *}" ]] && return 0
    [[ -L "$RESOLV_CONF" ]] && return 0
    if command -v dig > /dev/null 2>&1; then
        r=$(dns_query "${want%% *}" github.com); [[ "${r%% *}" == TIMEOUT ]] && { log "HEAL dns skipped: ${want%% *} does not answer (the system's own resolver stays)"; return 0; }
    fi
    dns_apply $want > /dev/null && log "HEAL dns: resolv.conf had been rewritten, restored $want"
}
dns_verify() {    # after a change: the new first resolver answers AND the system resolves a name through it
    [[ -n "${PFM_DNS_VERIFY_CMD:-}" ]] && { eval "$PFM_DNS_VERIFY_CMD" > /dev/null 2>&1; return; }
    local r; r=$(dns_query "$1" github.com); [[ "${r%% *}" == NOERROR ]] || return 1
    timeout 6 getent hosts github.com > /dev/null 2>&1
}
assist_dns() {
    ensure_tool dig "DNS benchmark" || return 1
    local doms=(github.com cloudflare.com google.com telegram.org) f ip name tmp i=0 specs=() labels=() h hn=0
    for f in "$PORTS_DIR"/*; do    # the names the tunnels themselves resolve: a resolver that cannot answer them is not an option
        [[ -f "$f" ]] || continue
        h=$(port_get "${f##*/}" P_DEST)
        valid_ip "$h" || [[ -z "$h" ]] && continue
        [[ " ${doms[*]} " == *" !$h "* ]] && continue                                       # one name, however many tunnels use it
        grep -qiwF -- "$h" "${PFM_HOSTS_FILE:-/etc/hosts}" 2> /dev/null && continue        # a name only /etc/hosts knows is no resolver's business
        doms+=("!$h"); hn=$((hn + 1))
    done
    echo -e "\n  ${B}${W}DNS benchmark${NC}\n  ${GR}Each resolver is asked $(( ${#doms[@]} - hn )) public names twice (cache speed) and 3 names that cannot exist (real lookup speed)$( ((hn)) && echo ", plus $hn name(s) your tunnels use" ).${NC}"
    echo -e "  ${GR}A resolver that answers a public name with a private address, invents answers for missing names, or cannot resolve your tunnels' names is rejected.${NC}\n"
    tmp=$(mktemp -d)
    while IFS='|' read -r name ips; do for ip in $ips; do specs+=("$ip"); labels+=("$name"); done; done < <(dns_candidates)
    for ip in $(dns_system_resolvers); do specs+=("$ip"); labels+=("(system)"); done
    local pids=()
    for ((i = 0; i < ${#specs[@]}; i++)); do dns_bench_one "${specs[i]}" "${doms[@]}" > "$tmp/$i" & pids+=($!); done
    wait "${pids[@]}" 2> /dev/null
    local rows=() sc
    for ((i = 0; i < ${#specs[@]}; i++)); do
        IFS='|' read -r spec ok tot warm fresh bogus nx alive rfail < "$tmp/$i"
        [[ -n "$spec" ]] || continue
        local note="" score=999999
        if (( alive == 0 )); then note="no answer (blocked / down)"
        elif (( bogus > 0 )); then note="returns private addresses - filtered/hijacked"
        elif (( nx > 0 )); then note="rewrites NXDOMAIN answers"
        elif (( ${rfail:-0} > 0 )); then note="cannot resolve ${rfail} name(s) your tunnels use"
        elif (( tot > 0 && ok * 100 / tot < 80 )); then note="fails $((tot - ok)) of $tot lookups"
        else score=$(awk -v w="$warm" -v c="$fresh" 'BEGIN { if (c < 0) c = w * 3; if (w < 0) w = c; printf "%d", w * 0.4 + c * 0.6 + 0.5 }'); fi
        rows+=("$(printf '%06d|%s|%s|%s|%s|%s/%s|%s' "$score" "${labels[i]}" "$spec" "$warm" "$fresh" "$ok" "$tot" "$note")")
    done
    rm -rf "$tmp"
    printf "   ${GR}%-14s %-16s %8s %8s %6s  %s${NC}\n" "resolver" "address" "cached" "fresh" "ok" "verdict"
    local first=1 best_ip=()
    while IFS='|' read -r score label addr warm fresh okp note; do
        if [[ -n "$note" ]]; then printf "   ${R}%-14s %-16s %8s %8s %6s  %s${NC}\n" "$label" "$addr" "-" "-" "$okp" "$note"
        else
            local mark=""
            if (( ${#best_ip[@]} < 2 )) && [[ " ${best_ip[*]} " != *" $addr "* ]]; then best_ip+=("$addr"); mark="${G}<- best${NC}"; fi
            printf "   %-14s %-16s %6s ms %6s ms %6s  %b\n" "$label" "$addr" "$warm" "$fresh" "$okp" "$mark"
        fi
    done < <(printf '%s\n' "${rows[@]}" | sort)
    echo ""
    if (( ${#best_ip[@]} == 0 )); then echo -e "  ${R}No resolver passed. Keep the current one.${NC}"; return 1; fi
    local cur_first; cur_first=$(awk '/^nameserver/ { print $2 }' "$RESOLV_CONF" 2> /dev/null | head -n "${#best_ip[@]}" | tr '\n' ' ')
    if [[ "$cur_first" == "${best_ip[*]} " ]]; then echo -e "  ${G}Your current resolvers (${best_ip[*]}) are already the best of the ones tested - nothing to change.${NC}"; return 0; fi
    echo -e "  ${GR}Current: $(dns_current_line)${NC}"
    echo -e "  ${GR}Proposed: ${best_ip[*]}   (mode: $(dns_mode))${NC}"
    [[ "$(dns_mode)" == classic ]] && echo -e "  ${GR}The first of your current resolvers stays behind them as a fallback.${NC}"
    confirm "Use these resolvers?" y || return 1
    dns_apply "${best_ip[@]}" || return 1
    sleep 1
    if dns_verify "${best_ip[0]}"; then tune_hist dns "resolvers -> ${best_ip[*]}"; echo -e "  ${G}Done.${NC} ${GR}Undo: Optimization Assistant -> Status & revert.${NC}"
    else echo -e "  ${R}Name resolution failed with the new resolvers - restoring the old ones.${NC}"; dns_revert > /dev/null; return 1; fi
}

# ── scan, quick optimise, status, revert ──
scan_row() {    # scan_row ok|warn|bad|info <label> <value> [hint]
    local m
    case "$1" in ok) m="${G}✓${NC}" ;; warn) m="${Y}!${NC}" ;; bad) m="${R}✗${NC}" ;; *) m="${GR}-${NC}" ;; esac
    printf "   %b %-20s %-26s ${GR}%s${NC}\n" "$m" "$2" "$3" "${4:-}"
}
assist_scan() {
    local virt cc qd rmax mem ct cm dev nfo n_ip=0 n_rl=0 n_ha=0 f
    virt=$(systemd-detect-virt 2> /dev/null); virt="${virt:-none}"           # on bare metal it prints "none" AND exits 1
    cc=$(sys_get net.ipv4.tcp_congestion_control); qd=$(sys_get net.core.default_qdisc)
    rmax=$(sys_get net.ipv4.tcp_rmem | awk '{ print $3 }')
    ct=$(sys_get net.netfilter.nf_conntrack_max); cm=$(sys_get net.netfilter.nf_conntrack_count)
    for f in "$PORTS_DIR"/*; do [[ -f "$f" ]] || continue; case "$(. "$f" 2> /dev/null; echo "$P_METHOD")" in realm) n_rl=$((n_rl + 1)) ;; haproxy) n_ha=$((n_ha + 1)) ;; *) n_ip=$((n_ip + 1)) ;; esac; done
    echo -e "  ${GR}This server: $(nproc) CPU, $(awk '/MemTotal/ { printf "%d", $2 / 1024 }' /proc/meminfo) MB RAM, $virt, kernel $(uname -r)${NC}"
    [[ "$virt" =~ ^(lxc|openvz|docker|container-other|systemd-nspawn|podman)$ ]] && echo -e "  ${Y}Container detected: some kernel settings may be locked by the host.${NC}"
    echo ""
    if [[ "$cc" == bbr ]]; then scan_row ok "Congestion control" "bbr"
    elif [[ "$(sys_get net.ipv4.tcp_available_congestion_control)" == *bbr* || -e /sys/module/tcp_bbr ]] || modinfo tcp_bbr > /dev/null 2>&1; then
        scan_row warn "Congestion control" "${cc:-?}" "BBR is available: faster on long / lossy paths ($n_rl realm + $n_ha HAProxy tunnel(s) benefit)"
    else scan_row info "Congestion control" "${cc:-?}" "BBR not available in this kernel"; fi
    if [[ -z "$qd" ]]; then scan_row info "Queue discipline" "n/a" "not adjustable here"
    elif [[ "$qd" =~ ^(fq|fq_codel|cake)$ ]]; then scan_row ok "Queue discipline" "$qd"
    else scan_row warn "Queue discipline" "$qd" "fq (or fq_codel) paces traffic and keeps queues short"; fi
    if [[ "$rmax" =~ ^[0-9]+$ ]]; then
        if (( rmax >= 33554432 )); then scan_row ok "TCP buffer limit" "$(( rmax / 1048576 )) MB"
        elif (( rmax >= 16777216 )); then scan_row warn "TCP buffer limit" "$(( rmax / 1048576 )) MB" "enough up to ~100 ms; long paths want 32-64 MB"
        else scan_row bad "TCP buffer limit" "$(( rmax / 1048576 )) MB" "caps single-connection speed on long paths"; fi
    fi
    if [[ -z "$(limits_plan)" ]]; then scan_row ok "Connection limits" "${cm:-?} / ${ct:-?} tracked"
    else scan_row warn "Connection limits" "${cm:-?} / ${ct:-?} tracked" "below recommendation for this RAM"; fi
    dev=$(nic_default_dev)
    if [[ -n "$dev" ]]; then
        nfo=$(nic_scan "$dev")
        local plan; plan=$(nic_plan "$dev")
        if [[ -n "$plan" ]]; then scan_row warn "Network card $dev" "$(kvget "$nfo" driver), $(kvget "$nfo" rxq) queue(s)" "can spread load over $(nproc) CPUs / fix offloads"
        else scan_row ok "Network card $dev" "$(kvget "$nfo" driver), $(kvget "$nfo" rxq) queue(s)"; fi
    fi
    scan_row info "DNS" "$(dns_current_line)" "$( [[ -s "$TUNE_DIR/dns.conf" ]] && echo "set by PFM" || echo "not benchmarked yet" )"
    scan_row info "Tunnels" "$n_ip iptables, $n_rl realm, $n_ha haproxy" ""
}
assist_recommended() {    # what the last Bench Tests asked for (newest first, one line per tunnel, last 7 days)
    local f port age any=0
    for f in "$BENCH_DIR"/*/last.reco; do
        [[ -s "$f" ]] || continue
        age=$(( $(date +%s) - $(stat -c %Y "$f") )); (( age > 604800 )) && continue
        port=$(basename "$(dirname "$f")")
        (( any == 0 )) && echo -e "\n  ${C}Recommended by your Bench Tests${NC}"
        any=1
        printf "   ${W}:%s${NC} ${GR}(%s ago)${NC} " "$port" "$( (( age >= 3600 )) && echo "$((age / 3600)) h" || echo "$((age / 60)) min" )"
        while IFS='|' read -r id why; do [[ -n "$id" ]] && printf "%s; " "$(assist_label "$id")"; done < "$f"; echo ""
    done
}
quick_plan() {    # every change Quick Optimize makes, as a table - nothing is applied that is not listed here
    local pl="" dev fq=""
    if [[ "$(sys_get net.ipv4.tcp_congestion_control)" == bbr ]] || bbr_available; then
        fq=fq; pl+=$(sysctl_row "congestion control" net.ipv4.tcp_congestion_control bbr)$'\n'
        sys_has net.core.default_qdisc && pl+=$(sysctl_row "queue discipline (default)" net.core.default_qdisc fq)$'\n'
    fi
    pl+=$(sysctl_row "TCP socket limit (rx)" net.core.rmem_max 33554432 raise)$'\n'
    pl+=$(sysctl_row "TCP socket limit (tx)" net.core.wmem_max 33554432 raise)$'\n'
    pl+=$(sysctl_row_tcpmem "TCP receive window max" net.ipv4.tcp_rmem 33554432)$'\n'
    pl+=$(sysctl_row_tcpmem "TCP send window max" net.ipv4.tcp_wmem 33554432)$'\n'
    pl+=$(limits_plan)$'\n'
    dev=$(nic_default_dev)
    [[ -n "$dev" ]] && pl+=$(nic_plan "$dev" "$fq")$'\n'
    echo "$pl" | sed '/^$/d'
}
assist_quick() {
    local plan; plan=$(quick_plan)
    echo -e "\n  ${B}${W}Quick Optimize${NC}  ${GR}safe settings for a forwarding server; values are only raised, never lowered${NC}\n"
    if [[ -z "$plan" ]]; then echo -e "  ${G}Nothing to do - this server already has the recommended settings.${NC}"; return 0; fi
    printf "   ${GR}%-26s %-22s    %s${NC}\n" "setting" "now" "proposed"; echo "$plan"
    echo -e "\n  ${GR}Not included (they need a measurement first): MTU per tunnel, DNS resolver, tunnel profiles - see the menu.${NC}"
    confirm "Apply all of this?" y || return 1
    local dev; dev=$(nic_default_dev); tune_count_reset
    if bbr_available; then
        tune_sysctl net.core.default_qdisc fq; tune_sysctl net.ipv4.tcp_congestion_control bbr
        grep -q tcp_bbr "$MODLOAD_FILE" 2> /dev/null || { mkdir -p "$(dirname "$MODLOAD_FILE")"; echo tcp_bbr > "$MODLOAD_FILE"; }
    fi
    tune_raise net.core.rmem_max 33554432; tune_raise net.core.wmem_max 33554432
    tune_raise_tcpmem net.ipv4.tcp_rmem 33554432; tune_raise_tcpmem net.ipv4.tcp_wmem 33554432
    limits_apply
    [[ -n "$dev" ]] && nic_apply "$dev"
    (( TUNE_OK > 0 )) && tune_hist quick "Quick Optimize applied"
    tune_done && echo -e "  ${GR}Run the Bench Test on a tunnel to see the effect; everything can be undone in Status & revert.${NC}"
}
assist_status() {
    echo -e "\n  ${B}${W}Status & revert${NC}\n"
    local ns nn nd np nm
    ns=$(grep -c . "$TUNE_DIR/sysctl.conf" 2> /dev/null); nn=$(grep -c . "$TUNE_DIR/nic.conf" 2> /dev/null)
    nd=0; [[ -s "$TUNE_DIR/dns.conf" ]] && nd=1
    np=$(grep -lsE "$TUNE_CFG_RE" "$PORTS_DIR"/* 2> /dev/null | wc -l)
    nm=$(grep -c . "$TUNE_DIR/mtu.devs" 2> /dev/null)
    echo -e "   kernel settings changed ..... ${W}${ns:-0}${NC}"
    echo -e "   network card settings ....... ${W}${nn:-0}${NC}"
    echo -e "   DNS changed ................. ${W}$([[ $nd == 1 ]] && echo "yes ($(kv_get "$TUNE_DIR/dns.conf" servers))" || echo no)${NC}"
    echo -e "   tunnels with a profile / MTU  ${W}${np:-0}${NC}"
    echo -e "   interfaces with a new MTU ... ${W}${nm:-0}${NC}"
    echo -e "\n  ${GR}Recent changes:${NC}"
    if [[ -s "$TUNE_DIR/history.log" ]]; then
        tail -n 12 "$TUNE_DIR/history.log" | while IFS='|' read -r ts area what; do printf "   ${GR}%s${NC}  %-8s %s\n" "$(date -d "@$ts" '+%m-%d %H:%M' 2> /dev/null)" "$area" "$what"; done
    else echo -e "   ${GR}none${NC}"; fi
}
tune_routes_flush() { local fam; for fam in -4 -6; do ip $fam route flush proto "$PFM_ROUTE_PROTO" 2> /dev/null; done; return 0; }      # every route the assistant ever made carries this protocol number
tune_revert_all() {    # tune_revert_all [quiet]
    local q="${1:-}" f dev n port m d dp
    n=$(tune_sysctl_revert); n=$(( n + $(tune_misc_revert) )); [[ -z "$q" ]] && echo -e "   kernel settings restored: $n"
    n=$(nic_revert); [[ -z "$q" ]] && echo -e "   network card settings restored: $n"
    n=$(dns_revert); [[ -z "$q" ]] && echo -e "   DNS restored: $n"
    if [[ -s "$TUNE_DIR/mtu.devs" ]]; then while IFS='=' read -r dev _; do [[ -n "$dev" ]] && reset_mtu "$dev"; done < "$TUNE_DIR/mtu.devs"; : > "$TUNE_DIR/mtu.devs"; fi
    for f in "$PORTS_DIR"/*; do
        [[ -f "$f" ]] || continue
        grep -qsE "$TUNE_CFG_RE" "$f" || continue            # only tunnels that really carry a profile / MTU are touched (the others keep running undisturbed)
        port="${f##*/}"; m=$(port_get "$port" P_METHOD); d=$(port_get "$port" P_DEST); dp=$(port_get "$port" P_DPORT)
        local had_profile=0; grep -qs '^P_PROFILE="\?[^" ]' "$f" && had_profile=1
        port_unset "$port" P_PROFILE; port_unset "$port" P_TUNE_MTU
        if (( had_profile )) && [[ "$(port_get "$port" P_BLOCKED)" != 1 ]]; then       # a blocked tunnel must not be started by a revert
            case "${m:-iptables}" in
                realm) create_realm_service "$port" "$d" "${dp:-$port}" 0 > /dev/null 2>&1; start_realm_service "$port" ;;
                haproxy) rebuild_haproxy_cfg > /dev/null 2>&1 ;;
            esac
        fi
        tune_apply_tunnel "$port" force
    done
    tune_routes_flush; rm -rf "$TUNE_DIR/ipcache"; rm -f "$TUNE_DIR"/heal.* "$TUNE_DIR/routes.stamp"
    [[ -z "$q" ]] && echo -e "   tunnel profiles / pinned MTUs cleared"
    tune_hist revert "all PFM tuning reverted"
    return 0
}
tune_restore() { tune_sysctl_restore; nic_restore; dns_heal; }       # boot: tunnel pieces return through apply_port_rules
tune_needs_heal() {    # 0 = this tunnel has tuning (profile / pinned MTU) whose route or MSS rules have disappeared
    local port="$1" ip attrs fam="-4" plen=32 cmd
    local P_DEST="" P_METHOD="iptables" P_DPORT="$port" P_PROFILE="" P_TUNE_MTU=""
    source "$PORTS_DIR/$port" 2> /dev/null
    [[ -n "$P_PROFILE$P_TUNE_MTU" ]] || return 1
    ip=$(tune_dest_ip "$P_DEST"); [[ -n "$ip" ]] || return 1
    is_ipv6 "$ip" && { fam="-6"; plen=128; }
    [[ "$(tune_route_get "$ip")" == local* ]] && return 1                 # an address of this server: there is no route to tune
    attrs=$(tune_dest_attrs "$ip")
    # a route that is not ours in the way means we never could: that is not "disappeared"
    if [[ -n "$attrs" && -z "$(ip $fam route show exact "$ip/$plen" proto "$PFM_ROUTE_PROTO" 2> /dev/null)" && -z "$(ip $fam route show exact "$ip/$plen" 2> /dev/null)" ]]; then return 0; fi
    if [[ "$P_METHOD" == iptables && "$P_TUNE_MTU" =~ ^[0-9]+$ ]]; then
        cmd=$(ipt "$P_DEST")
        $cmd -t mangle -S FORWARD 2> /dev/null | grep -qE "pfm_mss_${port}([ \"]|\$)" || return 0       # exact port: pfm_mss_443 is not pfm_mss_4430
    fi
    return 1
}
TUNE_REFRESH_GAP="${PFM_TUNE_REFRESH_GAP:-240}"
tune_routes_refresh() {    # a host route copies the next hop / source address of the route it shadows; a DHCP renewal or a failover makes the copy stale
    [[ -d "$TUNE_DIR" ]] || return 0               # the assistant was never used on this server: there is nothing of ours to refresh
    local stamp="$TUNE_DIR/routes.stamp" now last ip done_ips=" " port d m prof pmtu unresolved=0          # -> rebuild them from the routing table as it is now, at most every few minutes
    now=$(date +%s); last=$(cat "$stamp" 2> /dev/null); [[ "$last" =~ ^[0-9]+$ ]] || last=0
    (( now - last >= TUNE_REFRESH_GAP )) || return 0
    echo "$now" > "$stamp"
    while IFS='|' read -r port d m prof pmtu _; do
        [[ -n "$prof$pmtu" ]] || continue
        ip=$(tune_dest_ip "$d"); [[ -n "$ip" ]] || { unresolved=1; continue; }        # (a name that does not resolve right now keeps its route)
        [[ "$done_ips" != *" $ip "* ]] || continue
        done_ips+="$ip "; tune_apply_dest "$ip"
    done < <(tune_port_table)
    # routes of ours that no tuned tunnel points at any more (a hostname that moved to another address, a port file edited by hand).
    # Only while every name resolved - with an unknown name a live route cannot be told from a leftover - and only IPv4: the kernel prints an
    # IPv6 address in its own canonical spelling, which need not be the one typed in the port file.
    (( unresolved )) && return 0
    local r
    while read -r r _; do
        [[ -n "$r" ]] || continue
        [[ "$done_ips" == *" ${r%/*} "* ]] || ip -4 route del "$r" proto "$PFM_ROUTE_PROTO" 2> /dev/null
    done < <(ip -4 route show proto "$PFM_ROUTE_PROTO" 2> /dev/null)
    return 0
}
tune_heal() {    # from `pfm sync` (every 5 minutes): whatever lost its setting gets it back
    local d f port now last stamp
    d=$(tune_sysctl_drift); if [[ -n "$d" ]]; then tune_sysctl_restore; log "HEAL sysctl re-applied: $(echo $d)"; fi
    if nic_drift; then nic_restore; log "HEAL network card settings re-applied"; fi
    dns_heal
    if tune_any_config; then
        now=$(date +%s)
        for f in "$PORTS_DIR"/*; do
            [[ -f "$f" ]] || continue; port="${f##*/}"; stamp="$TUNE_DIR/heal.$port"
            tune_needs_heal "$port" || { rm -f "$stamp"; continue; }
            # a repair that did not stick (container, no xt_TCPMSS ...) is tried again after half an hour, not at every sync
            if [[ -r "$stamp" ]]; then last=$(cat "$stamp" 2> /dev/null); [[ "$last" =~ ^[0-9]+$ ]] && (( now - last < 1800 )) && continue; fi
            tune_apply_tunnel "$port" force
            if tune_needs_heal "$port"; then echo "$now" > "$stamp"; log "HEAL tuning of $port could not be restored (route / MSS rule); next try in 30 min"
            else rm -f "$stamp"; log "HEAL tuning of $port (route / MSS rule had disappeared)"; fi
        done
    fi
    tune_routes_refresh
    return 0
}

# ── menus ──
tune_badge() {    # "[Gaming / calls, MTU 1400]" next to a tunnel in the menus (nothing when it was never tuned)
    local pr mt lbl bits=""
    IFS='|' read -r pr mt <<< "$(P_PROFILE=""; P_TUNE_MTU=""; . "$PORTS_DIR/$1" 2> /dev/null; echo "${P_PROFILE:-}|${P_TUNE_MTU:-}")"
    [[ -n "$pr" ]] && { IFS='|' read -r lbl _ <<< "$(profile_info "$pr")"; bits="$lbl"; }
    [[ -n "$mt" ]] && bits="${bits:+$bits, }MTU $mt"
    [[ -n "$bits" ]] && echo -e "${G}[${bits}]${NC}"
    return 0
}
assist_pick_tunnel() {    # prints the chosen port (or nothing)
    local f p i=0 ports=() prof lbl
    for f in "$PORTS_DIR"/*; do
        [[ -f "$f" ]] || continue; p=$(basename "$f"); ports+=("$p"); i=$((i + 1))
        local P_DEST="" P_DPORT="$p" P_METHOD="iptables" P_PROFILE="" P_TUNE_MTU=""; source "$f"
        IFS='|' read -r lbl _ <<< "$(profile_info "$P_PROFILE")"
        printf "  ${W}%2d)${NC} :%-6s → %-22s [%-8s] profile: %-14s%s\n" "$i" "$p" "${P_DEST}:${P_DPORT}" "$P_METHOD" "$lbl" "${P_TUNE_MTU:+  MTU $P_TUNE_MTU}" >&2
    done
    (( i == 0 )) && { echo -e "  ${GR}No tunnels yet.${NC}" >&2; return 1; }
    echo -ne "\n  ${C}Tunnel number (0 = back):${NC} " >&2; local n; read -r n
    [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= i )) && echo "${ports[n-1]}"
}
assist_tune_menu() {    # assist_tune_menu [port]
    local port="${1:-}" c
    if [[ -z "$port" ]]; then header; echo -e "  ${B}${W}Tune a tunnel${NC}\n"; port=$(assist_pick_tunnel) || { pause; return; }; [[ -n "$port" ]] || return; fi
    header
    if [[ "$(port_get "$port" P_METHOD)" != realm && "$(port_get "$port" P_METHOD)" != haproxy ]]; then assist_profile_set "$port" balanced; pause; return; fi      # kernel NAT: explains what applies instead
    echo -e "  ${B}${W}Tune :$port${NC}  ${GR}what do you use this tunnel for?${NC}\n"
    local cur; cur=$(port_profile "$port"); cur="${cur:-balanced}"
    local k lbl what i=0
    for k in bandwidth gaming balanced multiuser; do
        i=$((i + 1)); IFS='|' read -r lbl what <<< "$(profile_info "$k")"
        printf "  ${W}%d)${NC} %-16s ${GR}%s${NC}%s\n" "$i" "$lbl" "$what" "$([[ "$k" == "$cur" ]] && echo "  ${G}<- active${NC}")"
    done
    echo -e "  ${W}0)${NC} Back"
    echo -ne "\n  ${C}Select:${NC} "; read -r c || return 0
    case "$c" in 1) assist_profile_set "$port" bandwidth ;; 2) assist_profile_set "$port" gaming ;; 3) assist_profile_set "$port" balanced ;; 4) assist_profile_set "$port" multiuser ;; *) return ;; esac
    pause
}
menu_assist() {
    local c port
    tune_init
    while true; do
        header; echo -e "  ${B}${W}Optimization Assistant${NC}\n"
        assist_scan
        assist_recommended
        echo ""
        echo -e "  ${W}1)${NC} Quick Optimize           ${GR}safe defaults: BBR, buffers, limits, network card${NC}"
        echo -e "  ${W}2)${NC} Tune a tunnel            ${GR}profile: gaming / max bandwidth / balanced / many users${NC}"
        echo -e "  ${W}3)${NC} MTU auto-tune            ${GR}find the best MTU of a tunnel's path${NC}"
        echo -e "  ${W}4)${NC} DNS benchmark            ${GR}test resolvers, keep the fastest honest one${NC}"
        echo -e "  ${W}5)${NC} BBR / TCP buffers / limits"
        echo -e "  ${W}6)${NC} Network card (NIC)       ${GR}queues, offloads, ring buffers${NC}"
        echo -e "  ${W}7)${NC} Bench Test               ${GR}measure a tunnel (also in Manage Tunnels)${NC}"
        echo -e "  ${W}8)${NC} Status & revert"
        echo -e "  ${W}0)${NC} Back"
        echo -ne "\n  ${C}Select:${NC} "; read -r c || return 0
        case "$c" in
            1) header; assist_quick; pause ;;
            2) assist_tune_menu ;;
            3) header; echo -e "  ${B}${W}MTU auto-tune${NC}\n"; port=$(assist_pick_tunnel) && [[ -n "$port" ]] && { assist_mtu "$port"; pause; } ;;
            4) header; assist_dns; pause ;;
            5) header; assist_bbr; assist_buffers "" 1000; assist_limits; pause ;;
            6) header; assist_nic; pause ;;
            7) header; echo -e "  ${B}${W}Bench Test${NC}\n"; port=$(assist_pick_tunnel) && [[ -n "$port" ]] && menu_bench "$port" ;;
            8) header; assist_status
               echo -e "\n  ${W}1)${NC} Revert everything the assistant changed   ${W}0)${NC} Back"
               echo -ne "\n  ${C}Select:${NC} "; read -r c
               [[ "$c" == 1 ]] && confirm "Restore the original settings (tunnels keep running)?" n && { echo ""; tune_revert_all; pause; } ;;
            0|"") return ;;
        esac
    done
}
cmd_optimize() {    # pfm optimize [quick|scan|status|revert|dns|mtu <port>|profile <port> <name>]
    check_root; tune_init
    case "${1:-menu}" in
        menu) menu_assist ;;
        scan) assist_scan ;;
        quick) assist_quick ;;
        status) assist_status ;;
        revert) tune_revert_all ;;
        dns) assist_dns ;;
        bbr) assist_bbr ;;
        nic) assist_nic ;;
        mtu) assist_mtu "${2:-}" ;;
        profile) assist_profile_set "${2:-}" "${3:-balanced}" ;;
        *) echo "usage: pfm optimize [quick|scan|status|revert|dns|bbr|nic|mtu <port>|profile <port> gaming|bandwidth|balanced|multiuser]"; return 1 ;;
    esac
}
# @@END assist@@
# @@CHUNK versions@@
# ═══════════════ INSTALL, SHORTCUTS & VERSIONS (v2.0) ═══════════════
# Every release published on GitHub can be installed from the panel. The program that gets replaced is always kept
# (with a copy of the tunnel list), so a bad update is one key away from being undone - even without internet.
PFM_BIN="/usr/local/bin/pfm"
PFM_ATOM="${PFM_ATOM:-https://github.com/$PFM_REPO/releases.atom}"
PFM_GIT_URL="${PFM_GIT_URL:-https://github.com/$PFM_REPO.git}"
LAST_SWITCH="$BACKUP_DIR/last-switch.env"
PFM_KEEP_BACKUPS=6
VER_TAG=(); VER_DATE=(); VER_INFO=(); VER_ONLINE=0

ver_norm() { local v="${1#[vV]}"; echo "$v"; }
ver_cmp() {    # ver_cmp 1.10 1.9 -> 1 | 0 | -1   (numeric, dot separated)
    awk -v a="$(ver_norm "$1")" -v b="$(ver_norm "$2")" 'BEGIN {
        na = split(a, x, "."); nb = split(b, y, "."); n = (na > nb) ? na : nb
        for (i = 1; i <= n; i++) { p = x[i] + 0; q = y[i] + 0; if (p != q) { print ((p > q) ? 1 : -1); exit } }
        print 0 }'
}
valid_tag() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,40}$ ]]; }
version_of_file() {    # the version a pfm.sh announces in its header ("" = not a PFM script)
    [[ -r "$1" ]] || return 1
    sed -nE '/^#[[:space:]]+Port Forward Manager v[0-9]/{s/^#[[:space:]]+Port Forward Manager v([0-9][0-9A-Za-z.+-]*).*/\1/p;q}' "$1" 2> /dev/null
}
installed_version() { local v; v=$(version_of_file "$PFM_BIN"); echo "${v:-$PFM_VERSION}"; }
raw_url_for() {    # where the pfm.sh of a release lives (follows PFM_REPO_RAW, so mirrors work)
    if [[ "$1" == main ]]; then echo "$PFM_REPO_RAW/pfm.sh"; else echo "${PFM_REPO_RAW%/*}/$1/pfm.sh"; fi
}
validate_pfm_script() {    # 0 = a complete, loadable PFM release; otherwise prints why not
    local f="$1" sz
    [[ -s "$f" ]] || { echo "the download is empty"; return 1; }
    sz=$(wc -c < "$f")
    (( sz > 20000 )) || { echo "only $sz bytes - not a PFM release (a proxy or login page instead of GitHub?)"; return 1; }
    [[ "$(head -c 12 "$f")" == '#!/bin/bash'* ]] || { echo "not a bash script"; return 1; }
    [[ -n "$(version_of_file "$f")" ]] || { echo "no PFM version header"; return 1; }
    grep -q '^PFM_DIR=' "$f" && grep -qx 'main "\$@"' "$f" || { echo "it does not look like a complete PFM script"; return 1; }
    bash -n "$f" 2> /dev/null || { echo "it has a syntax error"; return 1; }
}

# ── backups: the program that is about to be replaced + the tunnel list ──
file_sum() { [[ -f "$1" ]] || return 0; if command -v sha256sum > /dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else cksum "$1" | awk '{ print $1 "-" $2 }'; fi; }
bk_key() { local b="${1##*/}" t; b="${b%.*}"; t="${b##*-}"; b="${b%-*}"; echo "${b##*-}$t"; }      # pfm-v2.0-20261018-120000.sh -> 20261018120000
backup_files() {    # backup_files <name prefix> -> the saved files of that kind, newest first (by the time in the NAME: a copy keeps the age of the program it holds)
    local f
    for f in "$BACKUP_DIR"/"$1"*; do [[ -f "$f" ]] && echo "$(bk_key "$f") $f"; done | sort -r | cut -d' ' -f2-
}
backup_current() {    # prints the path of the saved program ("" = there was nothing to save); returns 1 when it could not be saved
    local ver ts last out="" n d=()
    [[ -f "$PFM_BIN" ]] || return 0
    mkdir -p "$BACKUP_DIR" 2> /dev/null && chmod 700 "$BACKUP_DIR" 2> /dev/null
    ver=$(version_of_file "$PFM_BIN"); ver="${ver//[^0-9A-Za-z.]/x}"; ver="${ver:-unknown}"; ts=$(date +%Y%m%d-%H%M%S)
    last=$(backup_files "pfm-v$ver-" | head -1)                    # the same program saved already: keep that one
    if [[ -n "$last" ]] && cmp -s "$last" "$PFM_BIN"; then out="$last"
    else
        out="$BACKUP_DIR/pfm-v$ver-$ts.sh"
        if ! cp "$PFM_BIN" "$out" 2> /dev/null || ! cmp -s "$PFM_BIN" "$out"; then rm -f "$out"; return 1; fi       # a cut-off copy (disk full) is no backup
    fi
    for n in ports users usage tune mtu; do [[ -d "$PFM_DIR/$n" ]] && d+=("$n"); done
    [[ -f "$PFM_CONF" ]] && d+=(pfm.conf)
    if (( ${#d[@]} )) && ! tar -czf "$BACKUP_DIR/data-v$ver-$ts.tgz" -C "$PFM_DIR" "${d[@]}" 2> /dev/null; then rm -f "$BACKUP_DIR/data-v$ver-$ts.tgz"; fi
    echo "$out"
}
prune_backups() {    # keep the newest few saved programs / tunnel lists; the files given as arguments are never touched
    local kind keep="$PFM_KEEP_BACKUPS" f n protect=" $* "
    for kind in pfm-v data-v; do
        n=0
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            n=$((n + 1)); (( n > keep )) || continue
            [[ "$protect" == *" $f "* ]] || rm -f -- "$f"
        done < <(backup_files "$kind")
    done
}
install_file_atomic() {    # install_file_atomic <src> <dst>: write next to it, then rename - a running copy never sees half a file
    local src="$1" dst="$2" tmp="$2.new.$$"
    cp "$src" "$tmp" && chmod 755 "$tmp" && mv -f "$tmp" "$dst" || { rm -f "$tmp"; return 1; }
}
install_self() {    # put this very script at /usr/local/bin/pfm; the program it replaces is saved first
    local src="${PFM_INSTALL_SRC:-$PFM_SELF}" tmp="" why nv cur bk
    if [[ -n "${PFM_INSTALL_SRC:-}" && ! -f "$PFM_INSTALL_SRC" ]]; then echo -e "  ${R}The file to install ($PFM_INSTALL_SRC) is gone.${NC}"; return 1; fi
    if [[ -n "$src" && "$src" == "$PFM_BIN" ]]; then chmod 755 "$PFM_BIN" 2> /dev/null; return 0; fi          # already running from there
    if [[ -z "$src" || ! -f "$src" || "$src" == /dev/* || "$src" == /proc/* ]]; then
        # started with `bash <(curl ...)` or `curl ... | bash -s install`: the text is gone, fetch the same file again
        tmp=$(mktemp "${TMPDIR:-/tmp}/pfm-install.XXXXXX") || return 1
        if ! GH_TIMEOUT=90 gh_fetch -o "$tmp" "$PFM_REPO_RAW/pfm.sh"; then
            rm -f "$tmp"; echo -e "  ${R}Could not download $PFM_REPO_RAW/pfm.sh${NC}  ${GR}(GitHub unreachable? see PFM_REPO_RAW / PFM_CURL_OPTS in $PFM_CONF)${NC}"; return 1
        fi
        src="$tmp"
    fi
    if why=$(validate_pfm_script "$src"); then :; else
        echo -e "  ${R}Not installing: ${why}${NC}"; [[ -n "$tmp" ]] && rm -f "$tmp"; return 1
    fi
    nv=$(version_of_file "$src")
    if [[ -n "$tmp" && "$nv" != "$PFM_VERSION" && -z "${PFM_HANDOFF:-}" ]]; then
        # the file GitHub serves now is another version than the copy that was just started: let that version do its own install
        echo -e "  ${GR}GitHub now serves v$nv (this copy is v$PFM_VERSION): continuing with v$nv${NC}"
        PFM_HANDOFF=1 bash "$tmp" install "$@"; local rc=$?; rm -f "$tmp"; exit $rc
    fi
    if [[ -f "$PFM_BIN" ]] && cmp -s "$src" "$PFM_BIN"; then chmod 755 "$PFM_BIN" 2> /dev/null; [[ -n "$tmp" ]] && rm -f "$tmp"; return 0; fi
    cur=$(installed_version)
    bk=$(backup_current) || { echo -e "  ${R}Could not save the program that is installed now (disk full?) - not replacing it.${NC}"; [[ -n "$tmp" ]] && rm -f "$tmp"; return 1; }
    [[ -n "$bk" ]] && record_switch "$cur" "$bk" "$nv" ""
    install_file_atomic "$src" "$PFM_BIN" || { echo -e "  ${R}Could not write $PFM_BIN${NC}"; [[ -n "$tmp" ]] && rm -f "$tmp"; return 1; }
    [[ -n "$bk" ]] && { record_switch "$cur" "$bk" "$nv" "$(file_sum "$PFM_BIN")"; prune_backups "$bk"; }
    [[ -n "$tmp" ]] && rm -f "$tmp"
    return 0
}
install_shortcuts() {    # `PFM` (capital) opens the panel from anywhere; `pfm` keeps working; tab completion for both
    ln -sf pfm /usr/local/bin/PFM 2> /dev/null
    case ":$PATH:" in *:/usr/local/bin:*) ;;      # /usr/local/bin is not on this PATH: link into /usr/bin, but never over a file that is not ours
        *) [[ -e /usr/bin/PFM || -L /usr/bin/PFM ]] || ln -s "$PFM_BIN" /usr/bin/PFM 2> /dev/null
           [[ -e /usr/bin/pfm || -L /usr/bin/pfm ]] || ln -s "$PFM_BIN" /usr/bin/pfm 2> /dev/null ;; esac
    if [[ -d /etc/bash_completion.d ]]; then
        cat > /etc/bash_completion.d/pfm << 'COMP'
_pfm_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}" cmd="${COMP_WORDS[1],,}" ports
    ports=$(ls /etc/pfm/ports 2> /dev/null)
    if (( COMP_CWORD == 1 )); then
        COMPREPLY=($(compgen -W "install uninstall restore sync json monitor doctor bench bench-server optimize versions switch update rollback version help" -- "${cur,,}"))
    else
        case "$cmd" in
            doctor) COMPREPLY=($(compgen -W "$ports" -- "$cur")) ;;
            bench) if (( COMP_CWORD == 2 )); then COMPREPLY=($(compgen -W "$ports" -- "$cur")); else COMPREPLY=($(compgen -W "quick full --peer --yes --mask" -- "$cur")); fi ;;
            optimize|tune) if (( COMP_CWORD == 2 )); then COMPREPLY=($(compgen -W "quick scan status revert dns bbr nic mtu profile" -- "$cur")); else COMPREPLY=($(compgen -W "$ports gaming bandwidth balanced multiuser" -- "$cur")); fi ;;
            switch) COMPREPLY=($(compgen -W "$(cat /etc/pfm/latest.list 2> /dev/null) main --yes" -- "$cur")) ;;
        esac
    fi
}
complete -F _pfm_complete pfm PFM
COMP
    fi
    if [[ ! -e "$PFM_CONF" ]]; then
        cat > "$PFM_CONF" << 'CONF'
# PFM settings - read by /usr/local/bin/pfm on every start; updates never overwrite this file.
# A server that cannot reach GitHub directly can use a mirror and/or a proxy (uncomment and edit):
#PFM_REPO_RAW="https://raw.githubusercontent.com/parham381/PFM/main"
#PFM_API="https://api.github.com/repos/parham381/PFM"
#PFM_CURL_OPTS="--proxy socks5h://127.0.0.1:1080"
# Where the realm binary is downloaded from (folder that contains realm-x86_64-unknown-linux-gnu.tar.gz etc.):
#PFM_REALM_URL="https://github.com/zhboner/realm/releases/latest/download"
CONF
        chmod 600 "$PFM_CONF"
    fi
}
remove_shortcuts() {
    local l t
    for l in /usr/local/bin/PFM /usr/bin/PFM /usr/bin/pfm; do   # only links that point at our program
        [[ -L "$l" ]] || continue
        t=$(readlink "$l"); [[ "$t" == pfm || "$t" == "$PFM_BIN" ]] && rm -f "$l"
    done
    rm -f /etc/bash_completion.d/pfm
}

# ── what releases exist ──
ver_parse_json() {    # GitHub "list releases" JSON on stdin -> tag|date|title (drafts skipped)
    local json tool="${PFM_JSON_TOOL:-auto}"; json=$(cat)
    if [[ "$tool" == auto ]]; then
        if command -v python3 > /dev/null 2>&1; then tool=python3; elif command -v jq > /dev/null 2>&1; then tool=jq; else tool="awk"; fi
    fi
    case "$tool" in
        python3) python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(d, list):
    sys.exit(1)
for r in d:
    if not isinstance(r, dict) or r.get("draft") or not r.get("tag_name"):
        continue
    title = str(r.get("name") or r["tag_name"]).replace("|", "/").replace("\n", " ")
    if r.get("prerelease"):
        title += " (pre-release)"
    print("%s|%s|%s" % (r["tag_name"], str(r.get("published_at") or "")[:10], title))
' <<< "$json" ;;
        jq) jq -r '.[] | select((.draft // false) | not) | select(.tag_name != null)
                | "\(.tag_name)|\((.published_at // "")[0:10])|\(((.name // .tag_name) | gsub("[|\n]"; " ")) + (if .prerelease then " (pre-release)" else "" end))"' <<< "$json" 2> /dev/null ;;
        *) awk '
            function emit() { if (tag != "" && !draft) print tag "|" date "|" (name != "" ? name : tag) (pre ? " (pre-release)" : "") }
            /"tag_name": *"/ { emit(); tag = $0; sub(/.*"tag_name": *"/, "", tag); sub(/".*/, "", tag); name = ""; date = ""; draft = 0; pre = 0; next }
            tag != "" && name == "" && /^ *"name": *"/ { name = $0; sub(/^ *"name": *"/, "", name); sub(/",? *$/, "", name); gsub(/\|/, "/", name); next }
            tag != "" && /"draft": *true/ { draft = 1 }
            tag != "" && /"prerelease": *true/ { pre = 1 }
            tag != "" && date == "" && /"published_at": *"/ { date = $0; sub(/.*"published_at": *"/, "", date); date = substr(date, 1, 10) }
            END { emit() }' <<< "$json" ;;
    esac
}
ver_parse_atom() {    # releases.atom on stdin -> tag|date|title
    awk '
        /<entry>/ { inent = 1; tag = ""; date = ""; title = "" }
        inent && /<link / && /\/releases\/tag\// { t = $0; sub(/.*\/releases\/tag\//, "", t); sub(/".*/, "", t); tag = t }
        inent && /<updated>/ { d = $0; sub(/.*<updated>/, "", d); date = substr(d, 1, 10) }
        inent && /<title>/ { t = $0; sub(/.*<title>/, "", t); sub(/<\/title>.*/, "", t); gsub(/\|/, "/", t); title = t }
        /<\/entry>/ { if (tag != "") print tag "|" date "|" (title != "" ? title : tag); inent = 0 }'
}
ver_sort_desc() {    # lines that start with a tag, newest version first, duplicates dropped
    awk -F'|' '{ v = $1; sub(/^[vV]/, "", v); n = split(v, p, "."); k = ""
                 for (i = 1; i <= 5; i++) k = k sprintf("%06d.", (i <= n ? p[i] + 0 : 0)); print k "\t" $0 }' | sort -r | cut -f2- | awk -F'|' '!seen[$1]++'
}
ver_list_remote() {    # tag|date|title for every release; GitHub API first, then the atom feed, then git tags
    local body out q=""
    [[ "$PFM_API" == http* ]] && q="?per_page=50"
    if body=$(gh_fetch -H 'Accept: application/vnd.github+json' "$PFM_API/releases$q" 2> /dev/null) && [[ "$body" == *tag_name* ]]; then
        out=$(ver_parse_json <<< "$body" 2> /dev/null | ver_sort_desc); [[ -n "$out" ]] && { echo "$out"; return 0; }
    fi
    if body=$(gh_fetch "$PFM_ATOM" 2> /dev/null) && [[ "$body" == *"<entry>"* ]]; then
        out=$(ver_parse_atom <<< "$body" | ver_sort_desc); [[ -n "$out" ]] && { echo "$out"; return 0; }
    fi
    if command -v git > /dev/null 2>&1; then
        out=$(timeout 10 git ls-remote --tags --refs "$PFM_GIT_URL" 2> /dev/null | sed -nE 's#.*refs/tags/(v?[0-9][0-9A-Za-z.+-]*)$#\1||#p' | ver_sort_desc)
        [[ -n "$out" ]] && { echo "$out"; return 0; }
    fi
    return 1
}
ver_list_local() {    # file|version|time   - programs saved on this server (they need no internet)
    local f b v ts t
    for f in "$BACKUP_DIR"/pfm-v*.sh; do
        [[ -f "$f" ]] || continue
        b=$(basename "$f" .sh); v="${b#pfm-v}"; ts=$(grep -oE '[0-9]{8}-[0-9]{6}$' <<< "$v"); v="${v%-"$ts"}"
        t=$(date -d "${ts:0:4}-${ts:4:2}-${ts:6:2} ${ts:9:2}:${ts:11:2}:${ts:13:2}" '+%Y-%m-%d %H:%M' 2> /dev/null || echo "$ts")
        echo "$ts|$f|$v|$t"
    done | sort -r | cut -d'|' -f2-
}
ver_is_pre() { [[ "$1" == *-rc* || "$1" == *-beta* || "$1" == *-alpha* || "$2" == *"(pre-release)"* ]]; }
ver_load() {    # fills VER_TAG/VER_DATE/VER_INFO from GitHub and remembers the newest stable tag
    local out tag date info i
    VER_TAG=(); VER_DATE=(); VER_INFO=(); VER_ONLINE=0
    out=$(ver_list_remote) || return 1
    VER_ONLINE=1
    while IFS='|' read -r tag date info; do
        [[ -n "$tag" ]] && valid_tag "$tag" || continue
        VER_TAG+=("$tag"); VER_DATE+=("$date"); VER_INFO+=("$info")
    done <<< "$out"
    if [[ -d "$PFM_DIR" ]]; then        # cache for the main menu hint and Tab completion (root only; silent otherwise)
        { printf '%s\n' "${VER_TAG[@]}" > "$PFM_DIR/latest.list"; } 2> /dev/null
        for i in "${!VER_TAG[@]}"; do
            ver_is_pre "${VER_TAG[i]}" "${VER_INFO[i]}" && continue
            { echo "${VER_TAG[i]}" > "$PFM_DIR/latest.ver"; } 2> /dev/null; break
        done
    fi
}
ver_latest() {    # newest stable tag found by ver_load
    local i
    for i in "${!VER_TAG[@]}"; do ver_is_pre "${VER_TAG[i]}" "${VER_INFO[i]}" || { echo "${VER_TAG[i]}"; return 0; }; done
    return 1
}
ver_notes() {    # release notes of one tag (python3 or jq needed to unpack them, otherwise the link)
    local body="" json url="https://github.com/$PFM_REPO/releases/tag/$1"
    json=$(gh_fetch -H 'Accept: application/vnd.github+json' "$PFM_API/releases/tags/$1" 2> /dev/null) || { echo "$url"; return 1; }
    if command -v python3 > /dev/null 2>&1; then body=$(python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("body") or "")' <<< "$json" 2> /dev/null)
    elif command -v jq > /dev/null 2>&1; then body=$(jq -r '.body // ""' <<< "$json" 2> /dev/null); fi
    if [[ -n "$body" ]]; then printf '%s\n' "$body" | tr -d '\r'; else echo "$url"; fi
}

# ── switching ──
assist_has_changes() {    # did the Optimization Assistant change anything an older version could not look after?
    [[ -s "$TUNE_DIR/sysctl.conf" || -s "$TUNE_DIR/nic.conf" || -s "$TUNE_DIR/dns.conf" || -s "$TUNE_DIR/mtu.devs" ]] && return 0
    tune_any_config
}
versions_verify() {    # one block per broken tunnel; prints nothing when all work. Returns the number of broken tunnels
    local f port probs bad=0
    for f in "$PORTS_DIR"/*; do
        [[ -f "$f" ]] || continue; port=$(basename "$f")
        probs=$(tunnel_problems "$port" 2> /dev/null)
        [[ -n "$probs" ]] && { bad=$((bad + 1)); echo "  :$port"; echo "$probs"; }
    done
    return "$bad"
}
count_tunnels() { local f n=0; for f in "$PORTS_DIR"/*; do [[ -f "$f" ]] && n=$((n + 1)); done; echo "$n"; }
install_release_file() {    # run the installer OF that release (its own rules/services/cron logic) without its menu. 0 = installed · 2 = in place, but that installer reported an error · 1 = could not install
    local f="$1" wrap log rc
    wrap=$(mktemp "${TMPDIR:-/tmp}/pfm-switch.XXXXXX") || return 1
    log=$(mktemp "${TMPDIR:-/tmp}/pfm-switch-log.XXXXXX") || { rm -f "$wrap"; return 1; }
    {
        # the release without its last line `main "$@"` (only the last one: a heredoc may contain the same text)
        awk '{ l[NR] = $0 } END { last = 0; for (i = NR; i >= 1; i--) if (l[i] == "main \"$@\"") { last = i; break }
                                  for (i = 1; i <= NR; i++) if (i != last) print l[i] }' "$f"
        cat << 'WRAP'
# --- appended by the version switcher: run that release's installer, but do not open its menu or clear the screen ---
cmd_menu() { :; }
header() { :; }
cp() {      # releases before 2.0 copy "this file" to /usr/local/bin/pfm: hand over the real release script instead of this wrapper
    if [[ "$1" == "$PFM_SWITCH_WRAPPER" && "$2" == /usr/local/bin/pfm ]]; then
        command cp "$PFM_SWITCH_SOURCE" /usr/local/bin/pfm.new.$$ && command chmod 755 /usr/local/bin/pfm.new.$$ && command mv -f /usr/local/bin/pfm.new.$$ /usr/local/bin/pfm
    else command cp "$@"; fi
}
cmd_install
WRAP
    } > "$wrap"
    PFM_SWITCH_WRAPPER="$wrap" PFM_SWITCH_SOURCE="$f" PFM_INSTALL_SRC="$f" PFM_NO_MENU=1 timeout 300 bash "$wrap" < /dev/null > "$log" 2>&1; rc=$?
    if (( rc != 0 )); then echo -e "  ${R}The installer of that version reported an error (exit $rc):${NC}"; tail -n 12 "$log" | sed 's/^/    /'; fi
    rm -f "$wrap" "$log"
    # the installer should have placed the file; make sure of it
    cmp -s "$f" "$PFM_BIN" || install_file_atomic "$f" "$PFM_BIN" || return 1
    chmod 755 "$PFM_BIN" 2> /dev/null
    (( rc == 0 )) || return 2
    return 0
}
record_switch() { printf 'FROM_VERSION=%s\nFROM_FILE=%s\nTO_VERSION=%s\nTO_SUM=%s\nAT=%s\n' "$1" "$2" "$3" "$4" "$(date +%s)" > "$LAST_SWITCH"; }
switch_to_file() {    # switch_to_file <pfm.sh> <label> -> 0 = installed and every tunnel works · 3 = installed but something is wrong (the caller offers the way back) · 1 = nothing was changed
    local f="$1" label="$2" cur new bk bad nt keep=1 probs why irc sum
    if why=$(validate_pfm_script "$f"); then :; else echo -e "  ${R}Refusing to install: ${why}${NC}"; return 1; fi
    cur=$(installed_version); new=$(version_of_file "$f"); nt=$(count_tunnels)
    echo -e "\n  ${B}${W}Switch${NC}  ${C}v${cur}${NC}  →  ${C}v${new}${NC}  ${GR}(${label})${NC}\n"
    if [[ "$cur" == "$new" ]] && cmp -s "$f" "$PFM_BIN"; then echo -e "  ${G}This exact version is already installed.${NC}"; return 0; fi
    echo -e "  ${GR}What happens:${NC}"
    echo -e "   1. the installed program and your tunnel list are saved (${BACKUP_DIR})"
    echo -e "   2. v${new} installs itself the way its own installer does (rules, services, cron)"
    echo -e "   3. all ${nt} tunnel(s) are checked - and you can go back with one key if something is wrong"
    echo -e "  ${GR}Tunnels, users and traffic counters are kept. Realm / HAProxy tunnels restart for a second or two.${NC}"
    if [[ "$(ver_cmp "$new" 2.0)" == -1 ]] && assist_has_changes; then
        echo -e "\n  ${Y}v${new} does not know the Optimization Assistant, so it cannot look after what the assistant changed${NC}"
        echo -e "  ${Y}(kernel settings, network card, DNS, tunnel profiles, pinned MTUs).${NC}"
        if [[ "${PFM_YES:-0}" == 1 ]]; then
            echo -e "  ${GR}Non-interactive run: those settings stay as they are (undo them later with: pfm optimize revert, in v2.0).${NC}"
        else
            echo -e "  ${GR}If you are switching because something went wrong, putting everything back to the original values is the safe choice.${NC}"
            confirm "Put those settings back to their original values after the switch?" n && keep=0
        fi
    fi
    echo ""; confirm "Switch to v${new} now?" y || { echo -e "  ${GR}Nothing changed.${NC}"; return 1; }
    bk=$(backup_current) || { echo -e "  ${R}Could not save the program that is installed now (disk full?) - nothing was changed.${NC}"; return 1; }
    [[ -n "$bk" ]] && echo -e "  ${G}✔${NC} saved: ${GR}${bk}${NC}"
    [[ -n "$bk" ]] && record_switch "$cur" "$bk" "$new" ""      # written first: the way back exists even if this process is killed half way
    echo -e "  ${GR}Installing v${new} (please do not interrupt) ...${NC}"
    trap '' HUP INT                                              # a dropped SSH session or a stray Ctrl+C must not leave the switch half done
    install_release_file "$f"; irc=$?
    trap - HUP INT
    if (( irc == 1 )); then echo -e "  ${R}Could not install v${new}.${NC}"; return 1; fi
    sum=$(file_sum "$PFM_BIN"); [[ -n "$bk" ]] && record_switch "$cur" "$bk" "$new" "$sum"
    if (( irc == 0 )); then echo -e "  ${G}✔${NC} v${new} installed"
    else echo -e "  ${Y}!${NC} v${new} is in place, but its installer reported an error (shown above): cron / services may not be up to date"; fi
    log "SWITCH v$cur -> v$new ($label)"
    (( keep == 0 )) && { tune_revert_all quiet > /dev/null 2>&1; echo -e "  ${G}✔${NC} assistant settings reverted"; }
    sleep 2                                                      # realm / haproxy need a moment to bind
    probs=$(versions_verify); bad=$?
    prune_backups "$bk" "$f"
    if (( bad == 0 )); then
        echo -e "  ${G}✔${NC} ${nt} tunnel(s) checked - all working"
        if [[ "$(ver_cmp "$new" 2.0)" == -1 && -n "$bk" ]]; then
            echo -e "\n  ${GR}v${new} has no switch / rollback command. To come back to v${cur}:${NC}"
            echo -e "    ${W}bash ${bk} install${NC}   ${GR}(from this server, no internet needed)${NC}"
            echo -e "    ${W}bash <(curl -sL ${PFM_REPO_RAW}/pfm.sh) install${NC}   ${GR}(newest release)${NC}"
        fi
        (( irc == 0 )) && return 0
        return 3
    fi
    echo -e "  ${R}✗ ${bad} of ${nt} tunnel(s) are not working with v${new}:${NC}"
    echo -e "${R}${probs}${NC}"
    return 3
}
switch_version() {    # switch_version <tag|main>
    local want="$1" tmp why rc label="release"
    if [[ "$want" != main ]] && ! valid_tag "$want"; then echo -e "  ${R}'$want' is not a valid version name${NC}"; return 1; fi
    [[ "$want" == main ]] && label="main - development version"
    tmp=$(mktemp "${TMPDIR:-/tmp}/pfm-release.XXXXXX") || return 1
    echo -e "  ${GR}Downloading ${want} ...${NC}"
    if ! GH_TIMEOUT=90 gh_fetch -o "$tmp" "$(raw_url_for "$want")"; then
        rm -f "$tmp"
        echo -e "  ${R}Could not download ${want}${NC} ${GR}($(raw_url_for "$want"))${NC}"
        echo -e "  ${GR}Check the version name and that this server can reach GitHub (mirror / proxy: $PFM_CONF).${NC}"
        return 1
    fi
    if why=$(validate_pfm_script "$tmp"); then :; else rm -f "$tmp"; echo -e "  ${R}Refusing to install ${want}: ${why}${NC}"; return 1; fi
    switch_to_file "$tmp" "$label"; rc=$?
    rm -f "$tmp"
    return "$rc"
}
rollback_version() {    # undo the last switch/update: install the program that was running before it
    local FROM_VERSION="" FROM_FILE="" TO_VERSION="" TO_SUM="" AT="" f v
    [[ -r "$LAST_SWITCH" ]] && source "$LAST_SWITCH"
    # trust the record only while it still describes what is installed; the saved copy must differ from the installed program
    if [[ -n "$FROM_FILE" && -f "$FROM_FILE" && ( -z "$TO_SUM" || "$TO_SUM" == "$(file_sum "$PFM_BIN")" ) ]] && ! cmp -s "$FROM_FILE" "$PFM_BIN"; then :
    else
        FROM_FILE=""        # otherwise: the newest saved program whose CONTENT differs from the installed one
        while IFS='|' read -r f v _; do cmp -s "$f" "$PFM_BIN" || { FROM_FILE="$f"; break; }; done < <(ver_list_local)
    fi
    [[ -n "$FROM_FILE" && -f "$FROM_FILE" ]] || { echo -e "  ${Y}There is no earlier version saved on this server.${NC}"; return 1; }
    switch_to_file "$FROM_FILE" "saved on this server"
}

# ── menu + CLI ──
switch_done() {    # after a switch attempt from the menu: leaves PFM when it worked (this running copy is the old version), else offers the way back
    local rc="$1"
    if (( rc == 0 )); then echo -e "\n  ${G}Done.${NC} Type ${W}PFM${NC} to open the panel of that version."; exit 0; fi
    if (( rc == 3 )) && confirm "Go back to the version you had before?" y; then
        rollback_version && { echo -e "\n  ${G}Done.${NC} Type ${W}PFM${NC} to open the panel."; exit 0; }
    fi
    return 1
}
menu_versions() {
    local act n i cur latest tag note loc lfile lver ltime base
    while true; do
        header; echo -e "  ${B}${W}Versions & Update${NC}\n"
        echo -ne "  ${GR}Reading the release list from GitHub ...${NC}\r"
        ver_load; echo -ne "\033[2K\r"
        cur=$(installed_version); latest=$(ver_latest)
        loc=(); while IFS='|' read -r lfile lver ltime; do [[ -n "$lfile" ]] && loc+=("$lfile|$lver|$ltime"); done < <(ver_list_local)
        if (( VER_ONLINE )); then
            if [[ -n "$latest" && "$(ver_cmp "$latest" "$cur")" == 1 ]]; then
                echo -e "  Installed ${C}v${cur}${NC}    Latest release ${G}${latest}${NC}  ${Y}← update available${NC} ${GR}(press u)${NC}\n"
            else echo -e "  Installed ${C}v${cur}${NC}    Latest release ${G}${latest:-?}${NC}  ${G}✔ up to date${NC}\n"; fi
            printf "  ${GR}%3s  %-9s %-11s %s${NC}\n" "#" "Version" "Released" "Release"
            echo -e "  ${GR}$(hr 60)${NC}"
            for i in "${!VER_TAG[@]}"; do
                tag="${VER_TAG[i]}"; note=""
                [[ "$(ver_norm "$tag")" == "$cur" ]] && note="  ${G}◀ installed${NC}"
                printf "  ${W}%3d${NC}  %-9s %-11s %s%b\n" "$((i + 1))" "$tag" "${VER_DATE[i]}" "${VER_INFO[i]}" "$note"
            done
        else
            echo -e "  Installed ${C}v${cur}${NC}\n"
            echo -e "  ${Y}GitHub could not be reached${NC} ${GR}(no internet, blocked, or rate-limited). A mirror or proxy can be set in ${PFM_CONF}.${NC}"
        fi
        base=${#VER_TAG[@]}
        if (( ${#loc[@]} )); then
            echo -e "\n  ${C}Saved on this server${NC} ${GR}(programs that were replaced; no internet needed)${NC}"
            for i in "${!loc[@]}"; do
                IFS='|' read -r lfile lver ltime <<< "${loc[i]}"
                printf "  ${W}%3d${NC}  v%-8s saved %s%s\n" "$((base + i + 1))" "$lver" "$ltime" "$([[ "$lver" == "$cur" ]] && echo '  (same as installed)')"
            done
        fi
        echo -e "\n  ${GR}number = switch to it · i<number> = what is in it · u = update to latest · r = roll back · m = main (development) · 0 = back${NC}"
        echo -ne "  ${C}>${NC} "; read -r act || exit 0
        case "$act" in
            ""|0|q) return ;;
            u) if [[ -z "$latest" ]]; then echo -e "  ${Y}No release list - nothing to update to.${NC}"
               elif [[ "$(ver_cmp "$latest" "$cur")" != 1 ]]; then echo -e "  ${G}You already have the newest release (v${cur}).${NC}"
               else switch_version "$latest"; switch_done $? ; fi
               pause ;;
            r) rollback_version; switch_done $?; pause ;;
            m) echo -e "  ${Y}main is the development branch: it can be ahead of the last release and unfinished.${NC}"
               if confirm "Install main anyway?" n; then switch_version main; switch_done $?; fi
               pause ;;
            i[0-9]*) n="${act#i}"
               if [[ "$n" =~ ^[0-9]+$ ]] && (( 10#$n >= 1 && 10#$n <= base )); then
                   n=$((10#$n)); header; echo -e "  ${B}${W}${VER_TAG[n-1]}${NC}\n"; ver_notes "${VER_TAG[n-1]}" | head -n 45
               else echo -e "  ${R}No such number${NC}"; fi
               pause ;;
            *[!0-9]*) echo -e "  ${R}?${NC}"; sleep 1 ;;
            *) n=$((10#$act))
               if (( n >= 1 && n <= base )); then switch_version "${VER_TAG[n-1]}"; switch_done $?
               elif (( n > base && n <= base + ${#loc[@]} )); then
                   IFS='|' read -r lfile lver ltime <<< "${loc[n - base - 1]}"
                   switch_to_file "$lfile" "saved on this server"; switch_done $?
               else echo -e "  ${R}No such number${NC}"; sleep 1; continue; fi
               pause ;;
        esac
    done
}
cmd_versions() {    # pfm versions | switch <tag> | update | rollback | version      (-y answers yes)
    local sub="$1" a target="" rc; shift
    for a in "$@"; do
        case "$a" in
            -y|--yes) PFM_YES=1 ;;
            -*) echo -e "  ${R}Unknown option: $a${NC}  ${GR}(PFM help)${NC}"; return 1 ;;
            *) [[ -z "$target" ]] && target="$a" ;;
        esac
    done
    case "$sub" in
        version)
            echo "PFM v$PFM_VERSION"
            [[ "$(installed_version)" != "$PFM_VERSION" ]] && echo "installed: v$(installed_version)"
            return 0 ;;
        versions)
            ver_load || echo -e "${Y}GitHub could not be reached.${NC}"
            local i cur; cur=$(installed_version)
            for i in "${!VER_TAG[@]}"; do printf "%-10s %-11s %s%s\n" "${VER_TAG[i]}" "${VER_DATE[i]}" "${VER_INFO[i]}" "$([[ "$(ver_norm "${VER_TAG[i]}")" == "$cur" ]] && echo '   <- installed')"; done
            local lf lv lt; while IFS='|' read -r lf lv lt; do [[ -n "$lf" ]] && echo "saved here: v$lv ($lt)"; done < <(ver_list_local)
            return 0 ;;
        switch)
            check_root
            [[ -n "$target" ]] || { echo "usage: pfm switch <version|main> [-y]     (see: pfm versions)"; return 1; }
            switch_version "$target"; rc=$?
            if (( rc == 3 )); then confirm "Go back to the version you had before?" y && rollback_version; fi
            return "$rc" ;;
        update|upgrade)
            check_root
            ver_load || { echo -e "${R}GitHub could not be reached.${NC} ${GR}Mirror / proxy settings: $PFM_CONF${NC}"; return 1; }
            local latest cur; latest=$(ver_latest); cur=$(installed_version)
            [[ -n "$latest" ]] || { echo "no release found"; return 1; }
            if [[ "$(ver_cmp "$latest" "$cur")" != 1 ]]; then echo -e "${G}Already up to date (v${cur}, latest release ${latest}).${NC}"; return 0; fi
            switch_version "$latest"; rc=$?
            if (( rc == 3 )); then confirm "Go back to the version you had before?" y && rollback_version; fi
            return "$rc" ;;
        rollback) check_root; rollback_version ;;
    esac
}
# @@END versions@@

# ═══════════════ MENU ═══════════════
cmd_menu() {
    while true; do
        header
        local newer=""; [[ -r "$PFM_DIR/latest.ver" ]] && newer=$(head -1 "$PFM_DIR/latest.ver")
        [[ -n "$newer" && "$(ver_cmp "$newer" "$PFM_VERSION")" == 1 ]] && echo -e "  ${Y}Update available: ${newer}${NC} ${GR}(11 = Versions & Update)${NC}\n"
        echo -e "  ${W}1)${NC}  Add Tunnel"
        echo -e "  ${W}2)${NC}  Manage Tunnels"
        echo -e "  ${W}3)${NC}  View Traffic"
        echo -e "  ${W}4)${NC}  Live Monitor"
        echo -e "  ${W}5)${NC}  Users"
        echo -e "  ${W}6)${NC}  MTU Settings"
        echo -e "  ${W}7)${NC}  Delete All Tunnels"
        echo -e "  ${W}8)${NC}  ${R}Uninstall Completely${NC}"
        echo -e "  ${W}9)${NC}  Diagnose (why is a tunnel not working?)"
        echo -e "  ${W}10)${NC} Optimization Assistant ${GR}(BBR, MTU, DNS, network card, gaming / bandwidth profiles)${NC}"
        echo -e "  ${W}11)${NC} Versions & Update ${GR}(switch to an earlier version if the newest has a problem)${NC}"
        echo -e "  ${W}0)${NC}  Exit"
        echo -ne "\n  ${C}Select:${NC} "
        read -r opt || exit 0
        case "$opt" in
            1) menu_add ;; 2) menu_manage ;; 3) menu_view ;; 4) cmd_monitor ;;
            5) menu_users ;; 6) menu_mtu ;;
            7) menu_reset ;; 8) cmd_uninstall ;;
            9) header; cmd_doctor; echo -ne "\n  ${GR}Enter...${NC}"; read -r ;;
            10) menu_assist ;; 11) menu_versions ;;
            0) exit 0 ;;
        esac
    done
}

# ═══════════════ ADD TUNNEL ═══════════════
menu_add() {
    header; echo -e "  ${B}${W}Add Tunnel${NC}\n"
    echo -e "  ${C}Forwarding engine:${NC}"
    echo -e "    ${W}1)${NC} haproxy     ${Y}TCP only${NC}  ${GR}(splice, fastest for TCP)${NC}"
    echo -e "    ${W}2)${NC} iptables    ${GR}(kernel NAT, TCP+UDP)${NC}"
    echo -e "    ${W}3)${NC} realm       ${GR}(zero-copy, TCP+UDP)${NC}"
    echo -e "    ${W}0)${NC} Back"
    echo -ne "  ${C}Select:${NC} "; read -r mopt
    [[ "$mopt" == "0" || -z "$mopt" ]] && return
    local method="haproxy"
    case "$mopt" in
        2) method="iptables" ;;
        3) method="realm"; if ! realm_installed; then install_realm || return; fi ;;
        *) method="haproxy"; if ! haproxy_installed; then install_haproxy || return; fi ;;
    esac
    echo ""
    echo -ne "  ${C}Port:${NC} "; read -r port
    [[ -z "$port" ]] && return
    valid_port "$port" || { echo -e "  ${R}Invalid port (1-65535)${NC}"; sleep 1; return; }
    [[ -f "$PORTS_DIR/$port" ]] && { echo -e "  ${R}Port $port exists${NC}"; sleep 1; return; }
    # realm/haproxy must bind the port themselves: refuse early when something else owns it
    local occ; occ=$(port_owner_name "$port")
    if [[ -n "$occ" ]]; then
        if [[ "$method" != "iptables" ]]; then
            echo -e "  ${R}Port $port is already used by '${occ}' - $method could not listen on it.${NC}"
            echo -e "  ${GR}Choose another port or stop that service first.${NC}"; sleep 3; return
        fi
        echo -ne "  ${Y}'${occ}' listens on port $port; the forward would take over its external traffic. Continue? (y/N):${NC} "
        read -r yn; [[ "$yn" != "y" && "$yn" != "Y" ]] && return
    fi
    # A port that is only DNAT-ed by another tool (other tunnel managers, Docker, firewalld...) has no
    # listener, so the check above calls it free - yet that rule takes the traffic before this tunnel.
    local other; other=$(foreign_report "$port" "$method")
    if [[ -n "$other" ]]; then
        echo -e "\n${Y}${other//✗/!}${NC}"
        echo -e "  ${GR}The new tunnel would look fine but receive nothing while that rule exists.${NC}"
        echo -ne "  ${Y}Add the tunnel anyway? (y/N):${NC} "
        read -r yn; [[ "$yn" != "y" && "$yn" != "Y" ]] && return
    fi
    echo -ne "  ${C}Destination IP:${NC} "; read -r dest
    [[ -z "$dest" ]] && return
    if ! valid_dest "$dest" "$method"; then
        local hint="IPv4/IPv6 address"; [[ "$method" != "iptables" ]] && hint="IPv4/IPv6 address or hostname"
        echo -e "  ${R}Invalid destination ($hint expected)${NC}"; sleep 2; return
    fi
    if ! valid_ip "$dest" && ! getent ahosts "$dest" > /dev/null 2>&1; then
        echo -e "  ${R}Cannot resolve '$dest'${NC}"; sleep 2; return
    fi
    echo -ne "  ${C}Destination Port [${port}]:${NC} "; read -r dport
    dport="${dport:-$port}"
    valid_port "$dport" || { echo -e "  ${R}Invalid destination port${NC}"; sleep 1; return; }
    echo -ne "  ${C}Owner:${NC} "; read -r owner
    [[ -z "$owner" ]] && return
    safe_text "$owner" || { echo -e "  ${R}Owner name must not contain \" \$ \` or \\ ${NC}"; sleep 2; return; }
    if [[ ! -f "$USERS_DIR/$owner" ]]; then
        echo -ne "  ${Y}Telegram ID:${NC} "; read -r tgid
        [[ "${tgid:-0}" =~ ^[0-9]+$ ]] || { echo -e "  ${R}Telegram ID must be a number${NC}"; sleep 1; return; }
        echo -e "CREATED=$(date +%s)\nENABLED=1\nTG_ID=${tgid:-0}" > "$USERS_DIR/$owner"
    fi
    echo -ne "  ${C}DL Limit GB (0=unlimited):${NC} "; read -r lgb; lgb="${lgb:-0}"
    valid_gb "$lgb" || { echo -e "  ${R}Limit must be a number${NC}"; sleep 1; return; }
    if ! dest_reachable "$dest" "$dport"; then
        echo -e "  ${Y}Warning: ${dest}:${dport} is not reachable over TCP from this server${NC}"
        echo -e "  ${GR}(wrong IP/port, destination down or blocking this server, or UDP-only service) - continuing${NC}"
    fi
    cat > "$PORTS_DIR/$port" << EOF
P_USER="$owner"
P_DEST="$dest"
P_DPORT="$dport"
P_LIMIT=$(gb_to_bytes "$lgb")
P_LIMIT_GB=$lgb
P_METHOD="$method"
P_PROTO="both"
P_CREATED=$(date +%s)
P_BLOCKED=0
EOF
    echo "0" > "$USAGE_DIR/$port"
    echo -e "\n  ${GR}Applying...${NC}"
    apply_rules "$port" "$dest" "$method" "$dport"
    # "applied" is not "working": verify, and undo everything when it is not
    local probs; probs=$(tunnel_problems "$port")
    if [[ -n "$probs" ]]; then
        echo -e "\n  ${R}${B}Tunnel :${port} was NOT created - it would not work:${NC}"
        echo -e "${R}${probs}${NC}"
        remove_rules "$port"; rm -f "${PORTS_DIR:?}/${port:?}" "${USAGE_DIR:?}/${port:?}"
        [[ "$method" == "haproxy" ]] && rebuild_haproxy_cfg > /dev/null 2>&1
        log "Add FAILED $port -> $dest:$dport method=$method: $(echo "$probs" | head -1 | sed 's/^ *//')"
        echo -ne "\n  ${GR}Enter...${NC}"; read -r; return
    fi
    local mtag=""; case "$method" in haproxy) mtag="${Y}haproxy${NC}";; realm) mtag="${MAG}realm${NC}";; *) mtag="${G}iptables${NC}";; esac
    echo -e "\n  ${G}OK!${NC} :${port} -> ${dest}:${dport} [${mtag}]  ${GR}(verified: listening / rules in place)${NC}"
    log "Added $port -> $dest:$dport method=$method user=$owner"
    echo -ne "\n  ${GR}Enter...${NC}"; read -r
}

# ═══════════════ MANAGE TUNNELS ═══════════════
menu_manage() {
    while true; do
        header; sync_all
        echo -e "  ${B}${W}Manage Tunnels${NC}\n"

        # List all tunnels
        local ports=() idx=0
        for pf in "$PORTS_DIR"/*; do
            [[ -f "$pf" ]] || continue
            local lp=$(basename "$pf")
            local P_USER="" P_DEST="" P_DPORT="$lp" P_LIMIT=0 P_BLOCKED=0 P_METHOD="iptables"
            source "$pf"
            idx=$((idx + 1))
            ports+=("$lp")
            local u=$(get_port_usage "$lp")
            local uh=$(human_bytes $u)
            local st="🟢" mclr="$G"
            [[ "$P_BLOCKED" == "1" ]] && st="🔴"
            case "$P_METHOD" in haproxy) mclr="$Y";; realm) mclr="$MAG";; esac
            printf "  ${W}%2d)${NC} Port ${C}%-6s${NC} → ${W}%-18s${NC} [${mclr}%s${NC}] %s  ${GR}%s${NC}  %s  %s\n" \
                "$idx" "$lp" "${P_DEST}:${P_DPORT}" "$P_METHOD" "$st" "$uh" "$P_USER" "$(tune_badge "$lp")"
        done

        if [[ $idx -eq 0 ]]; then
            echo -e "  ${GR}No tunnels yet.${NC}"
            echo -ne "\n  ${GR}Enter...${NC}"; read -r; return
        fi

        echo -e "\n  ${W}0)${NC} Back"
        echo -ne "\n  ${C}Select tunnel:${NC} "; read -r sel || return 0
        [[ -z "$sel" || "$sel" == "0" ]] && return
        [[ ! "$sel" =~ ^[0-9]+$ || "$sel" -gt "$idx" || "$sel" -lt 1 ]] && continue

        local sport="${ports[$((sel-1))]}"
        menu_tunnel_detail "$sport"
    done
}

menu_tunnel_detail() {
    local port="$1"
    while true; do
        [[ ! -f "$PORTS_DIR/$port" ]] && return
        header
        local P_USER="" P_DEST="" P_DPORT="$port" P_LIMIT=0 P_LIMIT_GB=0 P_BLOCKED=0 P_METHOD="iptables"
        source "$PORTS_DIR/$port"
        local u=$(get_port_usage "$port")
        local uh=$(human_bytes $u)
        local lh="Unlimited"; [[ "$P_LIMIT" -gt 0 ]] && lh=$(human_bytes $P_LIMIT)
        local st="${G}Active${NC}"; [[ "$P_BLOCKED" == "1" ]] && st="${R}Blocked${NC}"
        local mclr="$G"; case "$P_METHOD" in haproxy) mclr="$Y";; realm) mclr="$MAG";; esac

        echo -e "  ${B}${W}Tunnel — Port ${port}${NC}\n"
        echo -e "  ${GR}Listen Port:${NC} ${W}${port}${NC}"
        echo -e "  ${GR}Destination:${NC}  ${W}${P_DEST}:${P_DPORT}${NC}"
        echo -e "  ${GR}Engine:${NC}       ${mclr}${P_METHOD}${NC}"
        local tb; tb=$(tune_badge "$port"); [[ -n "$tb" ]] && echo -e "  ${GR}Tuning:${NC}       ${tb}"
        echo -e "  ${GR}Owner:${NC}        ${W}${P_USER}${NC}"
        echo -e "  ${GR}Used:${NC}         ${C}${uh}${NC} / ${lh}"
        echo -e "  ${GR}Status:${NC}       ${st}"
        echo ""

        local btxt="Block"; [[ "$P_BLOCKED" == "1" ]] && btxt="Unblock"
        echo -e "  ${W}1)${NC} Edit Destination IP"
        echo -e "  ${W}2)${NC} Edit Destination Port"
        echo -e "  ${W}3)${NC} Edit Listen Port"
        echo -e "  ${W}4)${NC} Edit Limit"
        echo -e "  ${W}5)${NC} Edit Owner"
        echo -e "  ${W}6)${NC} Reset Usage"
        echo -e "  ${W}7)${NC} ${btxt}"
        echo -e "  ${R}8)${NC} Delete Tunnel"
        echo -e "  ${W}9)${NC} Diagnose"
        echo -e "  ${W}10)${NC} ${C}Bench Test${NC} ${GR}(latency, loss, MTU, route, speed - with a report to share)${NC}"
        echo -e "  ${W}11)${NC} ${C}Tune${NC} ${GR}(gaming / max bandwidth / balanced / many users)${NC}  $(tune_badge "$port")"
        echo -e "  ${W}0)${NC} Back"
        echo -ne "\n  ${C}Select:${NC} "; read -r opt || return

        case "$opt" in
            1)  # Edit Destination IP
                echo -ne "  ${C}New Destination IP [${P_DEST}]:${NC} "; read -r newdest
                [[ -z "$newdest" ]] && continue
                valid_dest "$newdest" "$P_METHOD" || { echo -e "  ${R}Invalid destination${NC}"; sleep 1; continue; }
                if ! valid_ip "$newdest" && ! getent ahosts "$newdest" > /dev/null 2>&1; then
                    echo -e "  ${R}Cannot resolve '$newdest'${NC}"; sleep 1; continue
                fi
                sync_port_usage "$port"
                remove_rules "$port"
                sed -i "s|P_DEST=\"$P_DEST\"|P_DEST=\"$newdest\"|" "$PORTS_DIR/$port"
                if grep -q '^P_TUNE_MTU=' "$PORTS_DIR/$port"; then       # measured for the path to the OLD destination
                    port_unset "$port" P_TUNE_MTU
                    echo -e "  ${Y}The MTU pinned for the old destination was removed - run MTU auto-tune (Optimization Assistant) for the new one.${NC}"
                fi
                source "$PORTS_DIR/$port"
                apply_rules "$port" "$newdest" "$P_METHOD" "$P_DPORT"
                [[ "$P_BLOCKED" == "1" ]] && block_port "$port"
                rebuild_haproxy_cfg 2>/dev/null
                echo -e "  ${G}IP changed: ${P_DEST}${NC}"
                log "Edit $port dest=$newdest"; sleep 1; edit_report "$port" ;;

            2)  # Edit Destination Port
                echo -ne "  ${C}New Destination Port [${P_DPORT}]:${NC} "; read -r newdport
                [[ -z "$newdport" ]] && continue
                valid_port "$newdport" || { echo -e "  ${R}Invalid destination port${NC}"; sleep 1; continue; }
                sync_port_usage "$port"
                remove_rules "$port"
                sed -i "s/P_DPORT=\"$P_DPORT\"/P_DPORT=\"$newdport\"/" "$PORTS_DIR/$port"
                source "$PORTS_DIR/$port"
                apply_rules "$port" "$P_DEST" "$P_METHOD" "$P_DPORT"
                [[ "$P_BLOCKED" == "1" ]] && block_port "$port"
                rebuild_haproxy_cfg 2>/dev/null
                echo -e "  ${G}Destination port changed: ${P_DPORT}${NC}"
                log "Edit $port dport=$newdport"; sleep 1; edit_report "$port" ;;

            3)  # Edit Listen Port (rename) — destination port/IP are untouched
                echo -ne "  ${C}New Port [${port}]:${NC} "; read -r newport
                [[ -z "$newport" ]] && continue
                valid_port "$newport" || { echo -e "  ${R}Invalid port (1-65535)${NC}"; sleep 1; continue; }
                [[ -f "$PORTS_DIR/$newport" ]] && { echo -e "  ${R}Port $newport already exists${NC}"; sleep 1; continue; }
                if [[ "$P_METHOD" != "iptables" && -n "$(port_owner_name "$newport")" ]]; then
                    echo -e "  ${R}Port $newport is already used by '$(port_owner_name "$newport")'${NC}"; sleep 2; continue
                fi
                sync_port_usage "$port"
                remove_rules "$port"
                # Move files
                local old_usage=$(cat "$USAGE_DIR/$port" 2>/dev/null || echo 0)
                mv "$PORTS_DIR/$port" "$PORTS_DIR/$newport"
                echo "$old_usage" > "$USAGE_DIR/$newport"
                rm -f "$USAGE_DIR/$port"
                source "$PORTS_DIR/$newport"
                apply_rules "$newport" "$P_DEST" "$P_METHOD" "$P_DPORT"
                [[ "$P_BLOCKED" == "1" ]] && block_port "$newport"
                rebuild_haproxy_cfg 2>/dev/null
                echo -e "  ${G}Port changed: ${port} → ${newport}${NC}  ${GR}(destination unchanged: ${P_DEST}:${P_DPORT})${NC}"
                log "Edit port $port -> $newport"
                port="$newport"; sleep 1; edit_report "$port" ;;

            4)  # Edit Limit
                echo -ne "  ${C}New Limit GB (0=unlimited) [${P_LIMIT_GB}]:${NC} "; read -r newlimit
                [[ -z "$newlimit" ]] && continue
                valid_gb "$newlimit" || { echo -e "  ${R}Limit must be a number${NC}"; sleep 1; continue; }
                local nb=$(gb_to_bytes "$newlimit")
                sed -i "s/P_LIMIT=.*/P_LIMIT=$nb/" "$PORTS_DIR/$port"
                sed -i "s/P_LIMIT_GB=.*/P_LIMIT_GB=$newlimit/" "$PORTS_DIR/$port"
                echo -e "  ${G}Limit set to ${newlimit} GB${NC}"
                log "Edit $port limit=$newlimit GB"; sleep 1 ;;

            5)  # Edit Owner
                echo -ne "  ${C}New Owner [${P_USER}]:${NC} "; read -r newowner
                [[ -z "$newowner" ]] && continue
                safe_text "$newowner" || { echo -e "  ${R}Owner name must not contain \" \$ \` or \\ ${NC}"; sleep 2; continue; }
                if [[ ! -f "$USERS_DIR/$newowner" ]]; then
                    echo -ne "  ${Y}User not found. Create? Telegram ID:${NC} "; read -r tgid
                    [[ "$tgid" =~ ^[0-9]+$ ]] || { echo -e "  ${R}Telegram ID must be a number${NC}"; sleep 1; continue; }
                    echo -e "CREATED=$(date +%s)\nENABLED=1\nTG_ID=${tgid}" > "$USERS_DIR/$newowner"
                fi
                sed -i "s/P_USER=\"$P_USER\"/P_USER=\"$newowner\"/" "$PORTS_DIR/$port"
                echo -e "  ${G}Owner changed: ${newowner}${NC}"
                log "Edit $port owner=$newowner"; sleep 1 ;;

            6)  # Reset Usage
                echo "0" > "$USAGE_DIR/$port"
                local cmd=$(ipt "$P_DEST") chain=$(get_mangle_chain "$port")
                while IFS= read -r line; do
                    if echo "$line" | grep -q "pfm_dl_${port} "; then
                        local rn=$(echo "$line" | awk '{print $1}')
                        [[ "$rn" =~ ^[0-9]+$ ]] && $cmd -t mangle -Z "$chain" "$rn" 2>/dev/null
                    fi
                done < <($cmd -t mangle -L "$chain" -v -n -x --line-numbers 2>/dev/null)
                [[ "$P_BLOCKED" == "1" ]] && unblock_port "$port"
                echo -e "  ${G}Usage reset${NC}"; sleep 1 ;;

            7)  # Block/Unblock
                if [[ "$P_BLOCKED" == "1" ]]; then
                    unblock_port "$port"
                    echo -e "  ${G}Unblocked${NC}"
                else
                    block_port "$port"
                    echo -e "  ${Y}Blocked${NC}"
                fi; sleep 1 ;;

            8)  # Delete
                echo -ne "  ${R}Delete tunnel ${port}? (y/N):${NC} "; read -r yn
                [[ "$yn" != "y" && "$yn" != "Y" ]] && continue
                sync_port_usage "$port"
                remove_rules "$port"
                rm -f "$PORTS_DIR/$port" "$USAGE_DIR/$port"
                rebuild_haproxy_cfg 2>/dev/null
                echo -e "  ${G}Tunnel ${port} deleted${NC}"
                log "Deleted $port"; sleep 1; return ;;

            9)  # Diagnose
                header; cmd_doctor "$port"; echo -ne "\n  ${GR}Enter...${NC}"; read -r ;;

            10) menu_bench "$port" ;;
            11) assist_tune_menu "$port" ;;

            0) return ;;
        esac
    done
}

# ═══════════════ VIEW ═══════════════
menu_view() {
    header; sync_all
    echo -e "  ${B}${W}Traffic${NC}  ${GR}(Download Only)${NC}"
    echo -e "  ${GR}$(printf '%.0s─' $(seq 1 82))${NC}\n"
    local has=0
    for uf in "$USERS_DIR"/*; do
        [[ -f "$uf" ]] || continue
        local name=$(basename "$uf") ENABLED="" TG_ID=""; source "$uf"
        local hp=0
        for pf in "$PORTS_DIR"/*; do [[ -f "$pf" ]] || continue; local P_USER=""; source "$pf"
            [[ "$P_USER" == "$name" ]] && { hp=1; break; }; done
        [[ $hp -eq 0 ]] && continue; has=1
        local st="ON" sc="$G"; [[ "$ENABLED" == "0" ]] && { st="OFF"; sc="$R"; }
        echo -e "  ${B}${W}${name}${NC} [${sc}${st}${NC}]  ${GR}TG:${TG_ID}${NC}\n"
        printf "  ${GR}%-7s %-18s %-9s %-13s %-13s %-10s %-8s${NC}\n" "PORT" "DESTINATION" "ENGINE" "USED" "LIMIT" "REMAIN" "STATUS"
        echo -e "  ${GR}$(printf '%.0s─' $(seq 1 82))${NC}"
        local tu=0 tl=0
        for pf in "$PORTS_DIR"/*; do
            [[ -f "$pf" ]] || continue; local lp=$(basename "$pf")
            local P_USER="" P_DEST="" P_DPORT="$lp" P_LIMIT=0 P_LIMIT_GB=0 P_BLOCKED=0 P_METHOD="iptables"; source "$pf"
            [[ "$P_USER" != "$name" ]] && continue
            local u=$(get_port_usage "$lp")
            local uh=$(human_bytes $u) lh="Unlimited" rh="-"
            local stxt="Active" sclr="$G" uclr="$G" rclr=""
            local mclr="$G"; case "$P_METHOD" in haproxy) mclr="$Y";; realm) mclr="$MAG";; esac
            tu=$((tu+u))
            if [[ "$P_LIMIT" -gt 0 ]]; then
                lh=$(human_bytes $P_LIMIT); tl=$((tl+P_LIMIT))
                local rb=$((P_LIMIT-u)); ((rb<0))&&rb=0; rh=$(human_bytes $rb)
                local pct=$((u*100/P_LIMIT))
                ((pct>=90)) && { uclr="$R"; rclr="$R"; }; ((pct>=70&&pct<90)) && { uclr="$Y"; rclr="$Y"; }
                ((pct<70)) && rclr="$G"
            fi
            [[ "$P_BLOCKED" == "1" ]] && { stxt="Blocked"; sclr="$R"; }
            printf "  %-7s %-18s ${mclr}%-9s${NC} ${uclr}%-13s${NC} %-13s " "$lp" "${P_DEST}:${P_DPORT}" "$P_METHOD" "$uh" "$lh"
            [[ -n "$rclr" ]] && printf "${rclr}%-10s${NC} " "$rh" || printf "%-10s " "$rh"
            echo -e "${sclr}${stxt}${NC}"
        done
        echo -e "  ${GR}$(printf '%.0s─' $(seq 1 82))${NC}"
        local tlh="Unlimited" trh="-"
        [[ $tl -gt 0 ]] && { tlh=$(human_bytes $tl); local trb=$((tl-tu)); ((trb<0))&&trb=0; trh=$(human_bytes $trb); }
        printf "  ${W}%-7s %-18s %-9s %-13s %-13s %-10s${NC}\n\n" "TOTAL" "" "" "$(human_bytes $tu)" "$tlh" "$trh"
    done
    [[ $has -eq 0 ]] && echo -e "  ${GR}No tunnels yet.${NC}"
    echo -ne "  ${GR}Enter...${NC}"; read -r
}

# ═══════════════ MONITOR ═══════════════
cmd_monitor() {
    while true; do
        sync_all; clear
        echo -e "\n  ${B}${C}PFM Monitor${NC}  ${GR}$(date '+%H:%M:%S')${NC}"
        echo -e "  ${GR}$(printf '%.0s═' $(seq 1 78))${NC}"
        printf "\n  ${GR}%-7s %-18s %-9s %-8s %-15s %-6s${NC}\n" "PORT" "DEST" "ENGINE" "USER" "USED/LIMIT" "STATUS"
        echo -e "  ${GR}$(printf '%.0s─' $(seq 1 78))${NC}"
        for f in "$PORTS_DIR"/*; do
            [[ -f "$f" ]] || continue; local lp=$(basename "$f")
            local P_USER="" P_DEST="" P_DPORT="$lp" P_LIMIT=0 P_BLOCKED=0 P_METHOD="iptables"; source "$f"
            local u=$(get_port_usage "$lp")
            local uh=$(human_bytes $u) lh="Unlim" st="ON" sc="$G" uc=""
            local mclr="$G"; case "$P_METHOD" in haproxy) mclr="$Y";; realm) mclr="$MAG";; esac
            [[ "$P_LIMIT" -gt 0 ]] && { lh=$(human_bytes $P_LIMIT); local pct=$((u*100/P_LIMIT))
                ((pct>=90)) && uc="$R"; ((pct>=70&&pct<90)) && uc="$Y"; }
            [[ "$P_BLOCKED" == "1" ]] && { st="OFF"; sc="$R"; }
            if [[ "$P_BLOCKED" != "1" ]]; then case "$P_METHOD" in
                realm) realm_is_running "$lp" || { st="ERR"; sc="$R"; } ;;
                haproxy) haproxy_is_running || { st="ERR"; sc="$R"; } ;; esac; fi
            printf "  %-7s %-18s ${mclr}%-9s${NC} %-8s " "$lp" "${P_DEST}:${P_DPORT}" "$P_METHOD" "$P_USER"
            [[ -n "$uc" ]] && printf "${uc}%-15s${NC} " "${uh}/${lh}" || printf "%-15s " "${uh}/${lh}"
            echo -e "${sc}${st}${NC}"
        done
        echo -e "  ${GR}$(printf '%.0s─' $(seq 1 78))${NC}\n  ${GR}Ctrl+C to exit${NC}"; sleep 2
    done
}

# ═══════════════ TELEGRAM BOT MENU ═══════════════

# ═══════════════ MTU ═══════════════
menu_mtu() {
    header; echo -e "  ${B}${W}MTU Settings${NC}\n"
    echo -e "  ${GR}Current MTU per interface:${NC}"
    while IFS= read -r line; do
        local dev=$(echo "$line" | awk '{print $2}' | tr -d ':')
        local mtu=$(echo "$line" | grep -oP 'mtu \K[0-9]+')
        if [[ -n "$dev" && -n "$mtu" ]]; then
            local mark=""; [[ -f "$MTU_DIR/$dev" ]] && { local MTU_ORIG=""; source "$MTU_DIR/$dev"; mark="  ${GR}(was ${MTU_ORIG})${NC}"; }
            echo -e "    ${W}${dev}${NC}  MTU=${C}${mtu}${NC}${mark}"
        fi
    done < <(ip link show 2>/dev/null | grep "^[0-9]")
    echo -e "\n  ${W}1)${NC} Set MTU  ${W}2)${NC} Reset MTU  ${W}0)${NC} Back"
    echo -ne "\n  ${C}Select:${NC} "; read -r opt
    case "$opt" in
        1)  echo -ne "  ${C}Interface:${NC} "; read -r dev; [[ -z "$dev" ]] && return
            ip link show "$dev" > /dev/null 2>&1 || { echo -e "  ${R}Not found${NC}"; sleep 1; return; }
            echo -ne "  ${C}MTU value:${NC} "; read -r val; [[ ! "$val" =~ ^[0-9]+$ ]] && return
            save_mtu "$dev" "$val"; echo -e "  ${G}${dev} = ${val} (persistent)${NC}"; sleep 1 ;;
        2)  echo -ne "  ${C}Interface to reset:${NC} "; read -r dev; [[ -z "$dev" ]] && return
            if [[ -f "$MTU_DIR/$dev" ]]; then local MTU_ORIG=""; source "$MTU_DIR/$dev"; reset_mtu "$dev"
                echo -e "  ${G}${dev} restored to ${MTU_ORIG}${NC}"
            else echo -e "  ${Y}No saved MTU${NC}"; fi; sleep 1 ;;
        0) return ;;
    esac
}

# ═══════════════ USERS ═══════════════
menu_users() {
    while true; do
        header; echo -e "  ${W}1)${NC} Add  ${W}2)${NC} Remove  ${W}3)${NC} Toggle  ${W}4)${NC} List  ${W}0)${NC} Back"
        echo -ne "  ${C}Select:${NC} "; read -r opt || return 0
        case "$opt" in
            1) echo -ne "  ${C}Name:${NC} "; read -r un; echo -ne "  ${C}TG ID:${NC} "; read -r tg
               [[ -z "$un" || -z "$tg" ]] && continue
               [[ -f "$USERS_DIR/$un" ]] && { echo -e "  ${R}Exists${NC}"; sleep 1; continue; }
               echo -e "CREATED=$(date +%s)\nENABLED=1\nTG_ID=$tg" > "$USERS_DIR/$un"
               echo -e "  ${G}OK${NC}"; sleep 1 ;;
            2) echo -ne "  ${C}Name:${NC} "; read -r un
               [[ ! -f "$USERS_DIR/$un" ]] && { echo -e "  ${R}Not found${NC}"; sleep 1; continue; }
               for pf in "$PORTS_DIR"/*; do [[ -f "$pf" ]] || continue; local P_USER=""; source "$pf"
                   [[ "$P_USER" == "$un" ]] && { local lp=$(basename "$pf"); sync_port_usage "$lp"; remove_rules "$lp"
                   rm -f "$PORTS_DIR/$lp" "$USAGE_DIR/$lp"; }; done; rm -f "$USERS_DIR/$un"
               rebuild_haproxy_cfg 2>/dev/null; echo -e "  ${G}Removed${NC}"; sleep 1 ;;
            3) echo -ne "  ${C}Name:${NC} "; read -r un
               [[ ! -f "$USERS_DIR/$un" ]] && { echo -e "  ${R}Not found${NC}"; sleep 1; continue; }
               local ENABLED=""; source "$USERS_DIR/$un"
               if [[ "$ENABLED" == "1" ]]; then
                   sed -i "s/ENABLED=1/ENABLED=0/" "$USERS_DIR/$un"
                   for pf in "$PORTS_DIR"/*; do [[ -f "$pf" ]] || continue; source "$pf"
                       [[ "$P_USER" == "$un" ]] && block_port "$(basename "$pf")"; done
                   echo -e "  ${Y}Disabled${NC}"
               else
                   sed -i "s/ENABLED=0/ENABLED=1/" "$USERS_DIR/$un"
                   for pf in "$PORTS_DIR"/*; do [[ -f "$pf" ]] || continue; source "$pf"
                       [[ "$P_USER" == "$un" ]] && unblock_port "$(basename "$pf")"; done
                   echo -e "  ${G}Enabled${NC}"
               fi; sleep 1 ;;
            4) header; for uf in "$USERS_DIR"/*; do [[ -f "$uf" ]] || continue
                   local n=$(basename "$uf") ENABLED="" TG_ID=""; source "$uf"
                   local s="ON" c="$G"; [[ "$ENABLED" == "0" ]] && { s="OFF"; c="$R"; }
                   echo -e "  ${W}$n${NC} [${c}${s}${NC}] TG:${TG_ID}"; done
               echo -ne "\n  ${GR}Enter...${NC}"; read -r ;;
            0) return ;;
        esac
    done
}

# ═══════════════ PORTS ═══════════════
menu_ports() {
    while true; do
        header; echo -e "  ${W}1)${NC} Remove  ${W}2)${NC} Limit  ${W}3)${NC} Reset Usage  ${W}4)${NC} Block/Unblock  ${W}0)${NC} Back"
        echo -ne "  ${C}Select:${NC} "; read -r opt || return 0
        case "$opt" in
            1) echo -ne "  ${C}Port:${NC} "; read -r p; [[ ! -f "$PORTS_DIR/$p" ]] && { echo -e "  ${R}Not found${NC}"; sleep 1; continue; }
               sync_port_usage "$p"; remove_rules "$p"; rm -f "$PORTS_DIR/$p" "$USAGE_DIR/$p"
               rebuild_haproxy_cfg 2>/dev/null; echo -e "  ${G}Removed${NC}"; sleep 1 ;;
            2) echo -ne "  ${C}Port:${NC} "; read -r p; [[ ! -f "$PORTS_DIR/$p" ]] && { echo -e "  ${R}Not found${NC}"; sleep 1; continue; }
               echo -ne "  ${C}New limit GB:${NC} "; read -r nl
               sed -i "s/P_LIMIT=.*/P_LIMIT=$(gb_to_bytes "$nl")/" "$PORTS_DIR/$p"
               sed -i "s/P_LIMIT_GB=.*/P_LIMIT_GB=$nl/" "$PORTS_DIR/$p"; echo -e "  ${G}OK${NC}"; sleep 1 ;;
            3) echo -ne "  ${C}Port:${NC} "; read -r p; [[ ! -f "$PORTS_DIR/$p" ]] && { echo -e "  ${R}Not found${NC}"; sleep 1; continue; }
               echo "0" > "$USAGE_DIR/$p"; local P_DEST="" P_BLOCKED=0 P_METHOD="iptables"; source "$PORTS_DIR/$p"
               local cmd=$(ipt "$P_DEST") chain=$(get_mangle_chain "$p")
               while IFS= read -r line; do
                   echo "$line" | grep -q "pfm_dl_${p} " && { local rn=$(echo "$line"|awk '{print $1}')
                   [[ "$rn" =~ ^[0-9]+$ ]] && $cmd -t mangle -Z "$chain" "$rn" 2>/dev/null; }
               done < <($cmd -t mangle -L "$chain" -v -n -x --line-numbers 2>/dev/null)
               [[ "$P_BLOCKED" == "1" ]] && unblock_port "$p"; echo -e "  ${G}Reset OK${NC}"; sleep 1 ;;
            4) echo -ne "  ${C}Port:${NC} "; read -r p; [[ ! -f "$PORTS_DIR/$p" ]] && { echo -e "  ${R}Not found${NC}"; sleep 1; continue; }
               local P_BLOCKED=0; source "$PORTS_DIR/$p"
               if [[ "$P_BLOCKED" == "1" ]]; then unblock_port "$p"; echo -e "  ${G}Unblocked${NC}"
               else block_port "$p"; echo -e "  ${Y}Blocked${NC}"; fi; sleep 1 ;;
            0) return ;;
        esac
    done
}

menu_reset() {
    header; echo -ne "  ${R}Delete ALL tunnels? Type YES:${NC} "; read -r c
    [[ "$c" != "YES" ]] && return
    for f in "$PORTS_DIR"/*; do [[ -f "$f" ]] && remove_rules "$(basename "$f")"; done
    rm -f "$PORTS_DIR"/* "$USAGE_DIR"/*; rebuild_haproxy_cfg 2>/dev/null
    tune_routes_flush; [[ -f "$TUNE_DIR/mss.ports" ]] && : > "$TUNE_DIR/mss.ports"      # the routes of the assistant (they were recomputed from files that still existed a moment ago)
    echo -e "  ${G}All tunnels deleted${NC}"; log "Reset"; echo -ne "  ${GR}Enter...${NC}"; read -r
}

cmd_json() {
    # NO sync here - caller is responsible (bot: pfm sync; pfm json / menu: sync_all before)
    echo "{\"timestamp\":$(date +%s),\"users\":["
    local fu=1; for uf in "$USERS_DIR"/*; do [[ -f "$uf" ]] || continue
        local name=$(basename "$uf") ENABLED="" TG_ID=""; source "$uf"
        [[ $fu -eq 0 ]] && echo ","; fu=0
        echo "{\"name\":\"$name\",\"tg_id\":\"$TG_ID\",\"enabled\":$ENABLED,\"ports\":["
        local fp=1; for pf in "$PORTS_DIR"/*; do [[ -f "$pf" ]] || continue
            local lp=$(basename "$pf")
            local P_USER="" P_DEST="" P_DPORT="$lp" P_LIMIT=0 P_LIMIT_GB=0 P_BLOCKED=0 P_METHOD="iptables"; source "$pf"
            if [[ "$P_USER" == "$name" ]]; then
                local u=$(cat "$USAGE_DIR/$lp" 2>/dev/null || echo 0)
                [[ $fp -eq 0 ]] && echo ","; fp=0
                echo "{\"port\":$lp,\"dest\":\"${P_DEST}:${P_DPORT}\",\"method\":\"$P_METHOD\",\"dl_bytes\":$u,\"dl_human\":\"$(human_bytes $u)\",\"limit_bytes\":$P_LIMIT,\"limit_gb\":$P_LIMIT_GB,\"blocked\":$P_BLOCKED}"
            fi; done; echo -n "]}"; done; echo "]}"
}

cmd_uninstall() {
    check_root
    echo -e "\n  ${R}${B}This will remove EVERYTHING:${NC}"
    echo -e "  ${GR}- All tunnels and rules${NC}"
    echo -e "  ${GR}- All users and traffic data${NC}"
    echo -e "  ${GR}- HAProxy config and service${NC}"
    echo -e "  ${GR}- Realm services and binary${NC}"
    echo -e "  ${GR}- MTU settings and everything the Optimization Assistant changed (restored to the original values)${NC}"
    echo -e "  ${GR}- PFM config, backups of earlier versions, the binary and the PFM shortcut${NC}"
    echo -ne "\n  ${R}Type YES to confirm:${NC} "; read -r c
    [[ "$c" != "YES" ]] && return
    for f in "$PORTS_DIR"/*; do [[ -f "$f" ]] && remove_rules "$(basename "$f")"; done
    cleanup_old; remove_all_mtu
    tune_sysctl_revert > /dev/null; tune_misc_revert > /dev/null; nic_revert > /dev/null; dns_revert > /dev/null; tune_routes_flush     # give the system back its own settings
    for svc in /etc/systemd/system/pfm-realm-*.service; do
        [[ -f "$svc" ]] && { local sn=$(basename "$svc" .service); systemctl stop "$sn" 2>/dev/null; systemctl disable "$sn" 2>/dev/null; rm -f "$svc"; }
    done
    rm -f "$REALM_BIN"
    systemctl stop pfm-haproxy pfm-bot 2>/dev/null
    systemctl disable pfm-haproxy pfm-bot 2>/dev/null
    rm -f /etc/systemd/system/pfm-haproxy.service /etc/systemd/system/pfm-bot.service
    systemctl daemon-reload
    crontab -l 2>/dev/null | grep -v "pfm sync" | grep -v "ip link set mtu" | crontab -
    systemctl disable pfm-restore.service pfm-save.service 2>/dev/null || true
    rm -f /etc/systemd/system/pfm-restore.service /etc/systemd/system/pfm-save.service
    remove_shortcuts
    rm -rf "$PFM_DIR" /usr/local/bin/pfm /usr/local/bin/pfm-bot /usr/local/bin/pfm-cmd /etc/sysctl.d/99-pfm.conf /etc/sysctl.d/99-pfm.tune.conf "$LOG_FILE"
    systemctl daemon-reload
    echo -e "\n  ${G}PFM completely removed${NC}"; exit 0
}

usage() {
    echo -e "
  ${B}${C}PFM v${PFM_VERSION}${NC} - Port Forward Manager

  ${W}PFM${NC}                              open the panel (type it anywhere on the server)
  ${W}PFM install${NC}                      install / update to this file's version
  ${W}PFM uninstall${NC}                    remove PFM and everything it changed

  ${W}PFM doctor${NC} [port]                why does a tunnel not work?
  ${W}PFM bench${NC} <port> [quick|full] [--peer PORT] [--inet] [--yes] [--mask]
                                  measure a tunnel: latency, loss, MTU, route, speed (report you can screenshot)
  ${W}PFM bench-server${NC} [port] [client-ip] [minutes 1-120]
                                  run on the DESTINATION server: the helper the speed test talks to
  ${W}PFM optimize${NC} [quick|scan|status|revert|dns|bbr|nic|mtu <port>|profile <port> gaming|bandwidth|balanced|multiuser]
                                  Optimization Assistant

  ${W}PFM versions${NC}                     releases on GitHub and the ones saved on this server
  ${W}PFM switch${NC} <version> [-y]        install any release (v1.9, v2.0 ...)
  ${W}PFM update${NC} [-y]                  install the newest release
  ${W}PFM rollback${NC} [-y]                go back to the version used before the last switch / update
  ${W}PFM version${NC}

  ${W}PFM restore${NC} | ${W}sync${NC} | ${W}json${NC} | ${W}monitor${NC}   used by boot, cron and the Telegram bot
"
}

main() {
    local cmd="${1:-menu}" a; cmd="${cmd,,}"; [[ $# -gt 0 ]] && shift
    for a in "$@"; do [[ "$a" == -h || "$a" == --help ]] && { usage; return 0; }; done       # never start the real action for a help request
    case "$cmd" in
        install) cmd_install "$@" ;;
        uninstall) cmd_uninstall ;;
        restore) cmd_restore ;;
        sync) cmd_sync ;;
        json) cmd_json ;;
        monitor) cmd_monitor ;;
        doctor) cmd_doctor "$@" ;;
        bench) cmd_bench "$@" ;;
        bench-server|benchserver) cmd_bench_server "$@" ;;
        optimize|optimise|tune|assistant) cmd_optimize "$@" ;;
        versions|version|switch|update|upgrade|rollback) cmd_versions "$cmd" "$@" ;;
        -v|--version) echo "PFM v${PFM_VERSION}" ;;
        help|-h|--help) usage ;;
        menu|"") check_root; cmd_menu ;;
        *) echo -e "  ${R}Unknown command: ${cmd}${NC}"; usage; exit 1 ;;
    esac
}

main "$@"
