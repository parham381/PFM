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
#   Port Forward Manager v1.9
#
#   Telegram: https://t.me/AbrAfagh
#
#══════════════════════════════════════════════════════════════

PFM_DIR="/etc/pfm"
USERS_DIR="$PFM_DIR/users"
PORTS_DIR="$PFM_DIR/ports"
USAGE_DIR="$PFM_DIR/usage"
MTU_DIR="$PFM_DIR/mtu"
REALM_DIR="$PFM_DIR/realm"
REALM_BIN="/usr/local/bin/realm"
HEALTH_DIR="$PFM_DIR/health"
TRAFFIC_MIN=3                                  # packets that must arrive before "none was delivered" is believed
TRAFFIC_MIN_AGE=${PFM_TRAFFIC_MIN_AGE:-60}     # shortest window (s) a traffic verdict is based on
BASELINE_AGE=${PFM_BASELINE_AGE:-120}          # `pfm sync` renews its counter snapshot at most this often
WATCH_GAP=${PFM_WATCH_GAP:-30}                 # ...and looks at the tunnels at most this often (the bot calls sync a lot)
HAPROXY_CFG="$PFM_DIR/haproxy.cfg"
LOG_FILE="/var/log/pfm.log"
# If you fork this repo, change this to your own raw URL so `pfm install`
# (which also runs on self-update) fetches YOUR version, not upstream.
PFM_REPO_RAW="https://raw.githubusercontent.com/parham381/PFM/main"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
W='\033[1;37m'; GR='\033[0;90m'; NC='\033[0m'; B='\033[1m'
MAG='\033[0;35m'

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null; }
check_root() { [[ $EUID -ne 0 ]] && { echo -e "${R}Run as root${NC}"; exit 1; }; }

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
# "<rules> <packets>": how many rules carry the tag $1 in the iptables-save listing on stdin, and
# the sum of their packet counters
sum_tag_pkts() {
    awk -v T="--comment $1 " '
        /^\[[0-9]+:[0-9]+\] -A / { l = $0 " "; if (index(l, T) == 0) next
            p = $1; sub(/^\[/, "", p); sub(/:.*/, "", p); s += p; n++ }
        END { print n + 0, s + 0 }'
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
    read -r ns ps <<< "$(sum_tag_pkts "pfm_seen_$port" <<< "$d")"
    read -r ng pg <<< "$(sum_tag_pkts "pfm_got_$port" <<< "$d")"
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
    if curl -sL --connect-timeout 10 --max-time 60 \
        "https://github.com/zhboner/realm/releases/latest/download/realm-${arch}.tar.gz" \
        -o "$tmp/realm.tar.gz" 2>/dev/null; then
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
    local port="$1" dest="$2"; local dport="${3:-$port}"; mkdir -p "$REALM_DIR"
    cat > "$(realm_conf "$port")" << EOF
[network]
no_tcp = false
use_udp = true

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
    printf 'frontend ft_%s\n    bind *:%s\n    default_backend bk_%s\n\nbackend bk_%s\n    server srv1 %s:%s\n\n' \
        "$1" "$1" "$1" "$1" "$2" "$3"
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
    echo -e "  ${B}${C}       PFM - Port Forward Manager v1.9${NC}"
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
cmd_install() {
    check_root; header
    # Self-install: copy script to /usr/local/bin/pfm
    local src="${BASH_SOURCE[0]:-$0}"
    if [[ "$src" != "/usr/local/bin/pfm" ]]; then
        if [[ -f "$src" ]]; then
            cp "$src" /usr/local/bin/pfm
        else
            # Running from curl pipe - download again
            curl -sL "$PFM_REPO_RAW/pfm.sh" -o /usr/local/bin/pfm
        fi
        chmod +x /usr/local/bin/pfm
    fi
    mkdir -p "$USERS_DIR" "$PORTS_DIR" "$USAGE_DIR" "$MTU_DIR" "$REALM_DIR" "$HEALTH_DIR"
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
    echo -e "  ${G}PFM v1.9 installed${NC}"
    log "PFM v1.9 installed"; sleep 1; cmd_menu
}

cmd_restore() {
    check_root
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
    sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null 2>&1
    [[ -f /etc/sysctl.d/99-pfm.conf ]] && sysctl -p /etc/sysctl.d/99-pfm.conf > /dev/null 2>&1
    apply_all_mtu
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
    heal_rules
    # Health check all realm services + haproxy
    local f
    for f in "$PORTS_DIR"/*; do
        [[ -f "$f" ]] || continue
        realm_health_check "$(basename "$f")"
    done
    haproxy_health_check
    watch_tunnels
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
    [[ $nbad -eq 0 ]] && echo -e "  ${G}No problem found.${NC}" || echo -e "  ${R}${nbad} tunnel(s) with problems.${NC}  ${GR}Try: pfm restore  (a foreign NAT rule listed above must be removed by you)${NC}"
    return $((nbad > 0))
}

# ═══════════════ MENU ═══════════════
cmd_menu() {
    while true; do
        header
        echo -e "  ${W}1)${NC}  Add Tunnel"
        echo -e "  ${W}2)${NC}  Manage Tunnels"
        echo -e "  ${W}3)${NC}  View Traffic"
        echo -e "  ${W}4)${NC}  Live Monitor"
        echo -e "  ${W}5)${NC}  Users"
        echo -e "  ${W}6)${NC}  MTU Settings"
        echo -e "  ${W}7)${NC}  Delete All Tunnels"
        echo -e "  ${W}8)${NC}  ${R}Uninstall Completely${NC}"
        echo -e "  ${W}9)${NC}  Diagnose (why is a tunnel not working?)"
        echo -e "  ${W}0)${NC}  Exit"
        echo -ne "\n  ${C}Select:${NC} "
        read -r opt
        case "$opt" in
            1) menu_add ;; 2) menu_manage ;; 3) menu_view ;; 4) cmd_monitor ;;
            5) menu_users ;; 6) menu_mtu ;;
            7) menu_reset ;; 8) cmd_uninstall ;;
            9) header; cmd_doctor; echo -ne "\n  ${GR}Enter...${NC}"; read -r ;;
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
            printf "  ${W}%2d)${NC} Port ${C}%-6s${NC} → ${W}%-18s${NC} [${mclr}%s${NC}] %s  ${GR}%s${NC}  %s\n" \
                "$idx" "$lp" "${P_DEST}:${P_DPORT}" "$P_METHOD" "$st" "$uh" "$P_USER"
        done

        if [[ $idx -eq 0 ]]; then
            echo -e "  ${GR}No tunnels yet.${NC}"
            echo -ne "\n  ${GR}Enter...${NC}"; read -r; return
        fi

        echo -e "\n  ${W}0)${NC} Back"
        echo -ne "\n  ${C}Select tunnel:${NC} "; read -r sel
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
        echo -e "  ${W}0)${NC} Back"
        echo -ne "\n  ${C}Select:${NC} "; read -r opt

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
        echo -ne "  ${C}Select:${NC} "; read -r opt
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
        echo -ne "  ${C}Select:${NC} "; read -r opt
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
    echo -e "  ${GR}- MTU settings${NC}"
    echo -e "  ${GR}- PFM config and binary${NC}"
    echo -ne "\n  ${R}Type YES to confirm:${NC} "; read -r c
    [[ "$c" != "YES" ]] && return
    for f in "$PORTS_DIR"/*; do [[ -f "$f" ]] && remove_rules "$(basename "$f")"; done
    cleanup_old; remove_all_mtu
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
    rm -rf "$PFM_DIR" /usr/local/bin/pfm /usr/local/bin/pfm-bot /usr/local/bin/pfm-cmd /etc/sysctl.d/99-pfm.conf "$LOG_FILE"
    systemctl daemon-reload
    echo -e "\n  ${G}PFM completely removed${NC}"; exit 0
}

main() {
    case "${1:-menu}" in
        install) cmd_install ;; uninstall) cmd_uninstall ;;
        restore) cmd_restore ;; sync) cmd_sync ;;
        json) cmd_json ;; monitor) cmd_monitor ;;
        doctor) cmd_doctor "$2" ;;
        *) check_root; cmd_menu ;;
    esac
}

main "$@"
