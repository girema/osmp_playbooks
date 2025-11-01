#!/usr/bin/env bash
set -euo pipefail

# Set English locale if available
EngLocale=$(locale -a 2>/dev/null | grep -i "en_US.utf" | head -n1 || true)
if [ -n "${EngLocale:-}" ]; then export LANG="$EngLocale"; fi

# Defaults
ACTION=""
HOSTS=""
DEBUG=false

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --action) ACTION="${2:-}"; shift 2 ;;
    --host)   HOSTS="${2:-}";  shift 2 ;;
    --debug)  DEBUG=true;       shift ;;
    *) shift ;;
  esac
done

if [[ -z "${ACTION}" || -z "${HOSTS}" ]]; then
  echo "Usage: $0 --action <name> --host <h1,h2,...> [--debug]"
  exit 1
fi

# Function to check SSH availability (authenticate & no hostkey prompt)
is_host_alive() {
  ssh -q \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=5 \
    root@"$1" 'true' </dev/null
}

RESULTS=()
IFS=',' read -ra HOST_ARRAY <<< "$HOSTS"

for raw in "${HOST_ARRAY[@]}"; do
  host="$(echo "$raw" | xargs)"
  [[ -z "$host" ]] && continue

  if ! is_host_alive "$host"; then
    RESULTS+=("{\"host\":\"$host\",\"error\":\"unreachable\"}")
    continue
  fi

  case "$ACTION" in
    get_sudo_users)
      SUDO_USERS=$(
        ssh -q root@"$host" \
          'getent group sudo || getent group wheel || true' 2>/dev/null |
        awk -F: 'NF>=4{print $4}' | tr "," "\n" | awk "NF" |
        jq -R -s -c 'split("\n") | map(select(length>0))'
      )
      [[ -z "$SUDO_USERS" || "$SUDO_USERS" == "null" ]] && SUDO_USERS="[]"
      RESULTS+=("{\"host\":\"$host\",\"action\":\"get_sudo_users\",\"sudoUsers\":$SUDO_USERS}")
      ;;

    get_user_sessions)
      USER_SESSIONS=$(
        ssh -q root@"$host" "LANG=C w -h" 2>/dev/null |
        awk 'NF{
          user=$1; tty=$2; from=$3; login=$4; idle=$5;
          what="";
          for (i=6;i<=NF;i++){ what=what $i " " }
          sub(/^ +/,"",what); sub(/ +$/,"",what);
          printf("{\"user\":\"%s\",\"tty\":\"%s\",\"from\":\"%s\",\"login\":\"%s\",\"idle\":\"%s\",\"what\":\"%s\"}\n",user,tty,from,login,idle,what)
        }' | jq -s -c .
      )
      [[ -z "$USER_SESSIONS" || "$USER_SESSIONS" == "null" ]] && USER_SESSIONS="[]"
      RESULTS+=("{\"host\":\"$host\",\"action\":\"get_user_sessions\",\"userSessions\":$USER_SESSIONS}")
      ;;

    get_process_list)
      PROCESS_LIST=$(
        ssh -q root@"$host" "LANG=C ps aux --no-heading" 2>/dev/null |
        awk 'NF{
          user=$1; pid=$2; cpu=$3; mem=$4; vsz=$5; rss=$6; tty=$7; stat=$8; start=$9; time=$10;
          cmd=""; for(i=11;i<=NF;i++){cmd=cmd $i " "};
          sub(/^ +/,"",cmd); sub(/ +$/,"",cmd);
          printf("{\"user\":\"%s\",\"pid\":%s,\"cpu\":%s,\"mem\":%s,\"tty\":\"%s\",\"stat\":\"%s\",\"start\":\"%s\",\"time\":\"%s\",\"cmd\":\"%s\"}\n",user,pid,cpu,mem,tty,stat,start,time,cmd)
        }' | jq -s -c .
      )
      [[ -z "$PROCESS_LIST" || "$PROCESS_LIST" == "null" ]] && PROCESS_LIST="[]"
      RESULTS+=("{\"host\":\"$host\",\"action\":\"get_process_list\",\"processList\":$PROCESS_LIST}")
      ;;

    get_network_interfaces)
      IFACES=$(ssh -q root@"$host" "ip -j a" 2>/dev/null | jq -c '.' || echo "[]")
      [[ -z "$IFACES" || "$IFACES" == "null" ]] && IFACES="[]"
      RESULTS+=("{\"host\":\"$host\",\"action\":\"get_network_interfaces\",\"networkInterfaces\":$IFACES}")
      ;;

    get_network_connections)
      CONNECTIONS=$(
        ssh -q root@"$host" "LANG=C ss -tanup" 2>/dev/null |
        awk 'NR>1{
          proto=$1; local=$4; peer=$5; state=$6; extra="";
          for(i=7;i<=NF;i++){extra=extra" "$i};
          gsub(/\\/,"\\\\",proto); gsub(/\\/,"\\\\",local); gsub(/\\/,"\\\\",peer); gsub(/\\/,"\\\\",state); gsub(/\\/,"\\\\",extra);
          gsub(/"/,"\\\"",proto);  gsub(/"/,"\\\"",local); gsub(/"/,"\\\"",peer);  gsub(/"/,"\\\"",state);  gsub(/"/,"\\\"",extra);
          printf("{\"proto\":\"%s\",\"local\":\"%s\",\"peer\":\"%s\",\"state\":\"%s\",\"info\":\"%s\"}\n",proto,local,peer,state,extra);
        }' | jq -s -c .
      )
      [[ -z "$CONNECTIONS" || "$CONNECTIONS" == "null" ]] && CONNECTIONS="[]"
      RESULTS+=("{\"host\":\"$host\",\"action\":\"get_network_connections\",\"networkConnections\":$CONNECTIONS}")
      ;;

    get_daemons_list)
      OUT=$(
        ssh -q root@"$host" \
          "LANG=C systemctl list-unit-files --type=service --no-legend --no-pager" 2>/dev/null |
        awk 'NF && ($2=="enabled" || $2=="disabled" || $2=="stopped"){print $1, $2}'
      )
      DAEMONS=$(echo "$OUT" | awk 'NF{printf("{\"service\":\"%s\",\"state\":\"%s\"}\n",$1,$2)}' | jq -s -c .)
      [[ -z "$DAEMONS" || "$DAEMONS" == "null" ]] && DAEMONS="[]"
      RESULTS+=("{\"host\":\"$host\",\"action\":\"get_daemons_list\",\"daemons\":$DAEMONS}")
      ;;

    get_installed_packages)
      PACKAGES=$(
        ssh -q root@"$host" '
          if command -v rpm >/dev/null 2>&1; then rpm -qa;
          elif command -v dpkg >/dev/null 2>&1; then dpkg -l | awk "NR>5{print \$2}";
          fi
        ' 2>/dev/null | jq -R -s -c 'split("\n") | map(select(length>0))'
      )
      [[ -z "$PACKAGES" || "$PACKAGES" == "null" ]] && PACKAGES="[]"
      RESULTS+=("{\"host\":\"$host\",\"action\":\"get_installed_packages\",\"installedPackages\":$PACKAGES}")
      ;;

    get_iptables_rules)
      IPTABLES=$(ssh -q root@"$host" "sudo iptables -S 2>/dev/null || iptables -S" | jq -R -s -c 'split("\n") | map(select(length>0))')
      [[ -z "$IPTABLES" || "$IPTABLES" == "null" ]] && IPTABLES="[]"
      RESULTS+=("{\"host\":\"$host\",\"action\":\"get_iptables_rules\",\"iptablesRules\":$IPTABLES}")
      ;;

    get_system_info)
      SYSINFO=$(
        ssh -q root@"$host" '
          . /etc/os-release 2>/dev/null || true
          echo "{"
          echo "\"os_name\": \""${NAME:-unknown}"\","
          echo "\"os_version\": \""${VERSION:-unknown}"\","
          echo "\"kernel\": \""$(uname -r)"\","
          echo "\"hostname\": \""$(hostname)"\","
          echo "\"uptime\": \""$(uptime -p)"\","
          echo "\"cpu_count\": \""$(nproc)"\","
          echo "\"memory\": \""$(free -h | awk "/Mem:/{print \$2}")"\","
          echo "\"disk_usage\": ["; df -h --output=source,pcent,size,used,avail,target -x tmpfs -x devtmpfs | awk "NR>1{printf \"{\\\"filesystem\\\":\\\"%s\\\",\\\"use\\\":\\\"%s\\\",\\\"size\\\":\\\"%s\\\",\\\"used\\\":\\\"%s\\\",\\\"avail\\\":\\\"%s\\\",\\\"mount\\\":\\\"%s\\\"},\", \$1,\$2,\$3,\$4,\$5,\$6}"; echo "{}],"
          echo "\"network_mounts\": ["; mount | grep -E "nfs|cifs" | awk -F" " "{printf \"{\\\"mount\\\":\\\"%s\\\",\\\"on\\\":\\\"%s\\\"},\", \$1,\$3}" | sed "s/,$//"; echo "],"
          echo "\"firewall\": \""$( (firewall-cmd --state 2>/dev/null || ufw status 2>/dev/null || echo "none") | tr "\n" " ")"\""
          echo "}"
        ' 2>/dev/null
      )
      [[ -z "$SYSINFO" || "$SYSINFO" == "null" ]] && SYSINFO="{}"
      RESULTS+=("{\"host\":\"$host\",\"action\":\"get_system_info\",\"systemInfo\":$SYSINFO}")
      ;;

    disable_ssh_access)
      DISABLE_CMD='
        BACKUP="/etc/ssh/sshd_config.incident.bak"
        [ ! -f "$BACKUP" ] && cp /etc/ssh/sshd_config "$BACKUP"
        USERS=$(awk -F: '\''$3>=1000 && $1!="nobody" && $1!="root"{print $1}'\'' /etc/passwd | tr "\n" " " | sed "s/[[:space:]]\+/ /g")
        if [ -n "$USERS" ]; then
          echo "$USERS" > /etc/ssh/disabled_users.list
          if grep -q "^DenyUsers" /etc/ssh/sshd_config; then
            sed -i "s/^DenyUsers.*/DenyUsers $USERS/" /etc/ssh/sshd_config
          else
            echo "DenyUsers $USERS" >> /etc/ssh/sshd_config
          fi
        fi
        systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null
        echo "$USERS"
      '
      USERS=$(ssh -q root@"$host" "$DISABLE_CMD" 2>/dev/null)
      RESULTS+=("{\"host\":\"$host\",\"action\":\"disable_ssh_access\",\"result\":\"SSH access disabled for $USERS (except root)\"}")
      ;;

    enable_ssh_access)
      ENABLE_CMD='
        BACKUP="/etc/ssh/sshd_config.incident.bak"
        USERS=""
        if [ -f /etc/ssh/disabled_users.list ]; then
          USERS=$(cat /etc/ssh/disabled_users.list)
          rm -f /etc/ssh/disabled_users.list
        fi
        if [ -f "$BACKUP" ]; then
          cp "$BACKUP" /etc/ssh/sshd_config
        else
          sed -i "/^DenyUsers/d" /etc/ssh/sshd_config
        fi
        systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null
        echo "$USERS"
      '
      USERS=$(ssh -q root@"$host" "$ENABLE_CMD" 2>/dev/null)
      RESULTS+=("{\"host\":\"$host\",\"action\":\"enable_ssh_access\",\"result\":\"SSH access restored for $USERS (except root)\"}")
      ;;

    remove_from_admins)
      REMOVE_CMD='
        BACKUP="/etc/group.incident.bak"
        [ ! -f "$BACKUP" ] && cp /etc/group "$BACKUP"
        REMOVED=""
        for grp in sudo wheel; do
          if getent group "$grp" >/dev/null; then
            users=$(getent group "$grp" | awk -F: "{print \$4}" | tr "," " ")
            for u in $users; do
              [ "$u" = "root" ] && continue
              gpasswd -d "$u" "$grp" >/dev/null 2>&1 && REMOVED="$REMOVED $u"
            done
          fi
        done
        echo "$REMOVED" > /etc/ssh/removed_admins.list
        echo "$REMOVED"
      '
      REMOVED=$(ssh -q root@"$host" "$REMOVE_CMD" 2>/dev/null)
      RESULTS+=("{\"host\":\"$host\",\"action\":\"remove_from_admins\",\"result\":\"Removed from admin groups:$REMOVED\"}")
      ;;

    restore_admins_access)
      RESTORE_CMD='
        if [ -f /etc/ssh/removed_admins.list ]; then
          RESTORE=$(cat /etc/ssh/removed_admins.list)
          for grp in sudo wheel; do
            if getent group "$grp" >/dev/null; then
              for u in $RESTORE; do
                id "$u" >/dev/null 2>&1 && usermod -aG "$grp" "$u" >/dev/null 2>&1
              done
            fi
          done
          rm -f /etc/ssh/removed_admins.list
          echo "$RESTORE"
        fi
      '
      RESTORED=$(ssh -q root@"$host" "$RESTORE_CMD" 2>/dev/null)
      RESULTS+=("{\"host\":\"$host\",\"action\":\"restore_admins_access\",\"result\":\"Restored admin access for$RESTORED\"}")
      ;;

    collect_cron_jobs)
      CRON_INFO=$(
        ssh -q root@"$host" 'bash -s' <<'REMOTE'
echo "["
first=true

parse_cron_line() {
  local user="$1"
  local file="$2"
  local line="$3"

  # Trim leading/trailing whitespace
  line="$(echo "$line" | sed "s/^[[:space:]]*//;s/[[:space:]]*$//")"
  # Skip empty lines and pure comments
  if [ -z "$line" ] || echo "$line" | grep -q "^[[:space:]]*#"; then
    return 1
  fi

  # Handle @special lines
  if echo "$line" | grep -q "^@[a-zA-Z]"; then
    local spec cmd
    spec=$(echo "$line" | awk '{print $1}')
    cmd=$(echo "$line" | cut -d" " -f2-)
    [ -z "$cmd" ] && return 1
    $first || echo ","
    echo -n "{\"user\":\"$user\",\"schedule\":\"$spec\",\"command\":\"$(echo "$cmd" | sed 's/\"/\\\"/g')\"}"
    first=false
    return 0
  fi

  # Handle standard 5-field format
  local fields
  fields=$(echo "$line" | awk '{print NF}')
  if [ "$fields" -ge 6 ]; then
    local min hour day month wday cmd
    min=$(echo "$line" | awk '{print $1}')
    hour=$(echo "$line" | awk '{print $2}')
    day=$(echo "$line" | awk '{print $3}')
    month=$(echo "$line" | awk '{print $4}')
    wday=$(echo "$line" | awk '{print $5}')
    cmd=$(echo "$line" | cut -d" " -f6-)
    [ -z "$cmd" ] && return 1
    $first || echo ","
    echo -n "{\"user\":\"$user\",\"schedule\":\"$min $hour $day $month $wday\",\"command\":\"$(echo "$cmd" | sed 's/\"/\\\"/g')\"}"
    first=false
    return 0
  fi

  return 1
}

collected_any=false

  # Skip /etc/cron.daily, /etc/cron.weekly, etc. — those are shell scripts, not crontabs
  for dir in /etc/crontab /etc/cron.d /var/spool/cron /var/spool/cron/crontabs; do
  [ -e "$dir" ] || continue
  if [ -f "$dir" ]; then
    files="$dir"
  else
    files=$(find "$dir" -type f 2>/dev/null | grep -v '\.placeholder$' || true)
  fi

  for file in $files; do
    [ -f "$file" ] || continue
    user=""
    [[ "$file" == /var/spool/cron/* || "$file" == /var/spool/cron/crontabs/* ]] && user=$(basename "$file")

    while IFS= read -r line || [ -n "$line" ]; do
      if parse_cron_line "$user" "$file" "$line"; then
        collected_any=true
      fi
    done < "$file"
  done
done

#
# If no cron jobs found, fallback to direct grep with awk-based parsing
if ! $collected_any; then
  echo "DEBUG: Fallback cron grep executing..." >&2
  echo "DEBUG: Running grep on /var/spool/cron and /var/spool/cron/crontabs" >&2
  grep -r "" /var/spool/cron /var/spool/cron/crontabs 2>/dev/null | head -n 30 >&2
  echo "DEBUG: Starting awk parsing..." >&2
  PARSED=$(grep -r "" /var/spool/cron /var/spool/cron/crontabs 2>/dev/null | \
  awk -F':' '
    {
      file=$1; sub(/^[[:space:]]*/,"",file);
      line=$0; sub(/^[^:]*:/,"",line);
      if (line ~ /^[[:space:]]*#/ || line ~ /^[[:space:]]*$/) next;
      user="";
      if (file ~ /^\/var\/spool\/cron\//) {
        n=split(file,parts,"/"); user=parts[n];
      } else if (file ~ /^\/var\/spool\/cron\/crontabs\//) {
        n=split(file,parts,"/"); user=parts[n];
      }
      gsub(/"/, "\\\"", line);
      if (match(line,/^@[a-zA-Z]+/)) {
        split(line,arr," "); spec=arr[1]; cmd=substr(line,length(spec)+2);
        gsub(/"/, "\\\"", cmd);
        printf("{\"user\":\"%s\",\"schedule\":\"%s\",\"command\":\"%s\"},",user,spec,cmd);
      } else {
        split(line,arr," "); if (length(arr)<6) next;
        cmd="";
        for(i=6;i<=length(arr);i++){cmd = cmd arr[i] " ";}
        gsub(/^ +| +$/,"",cmd);
        gsub(/"/, "\\\"", cmd);
        printf("{\"user\":\"%s\",\"schedule\":\"%s %s %s %s %s\",\"command\":\"%s\"},",user,arr[1],arr[2],arr[3],arr[4],arr[5],cmd);
      }
    }
  ' | sed 's/,$//' | awk 'BEGIN{print "["}{print}END{print "]"}')
  echo "DEBUG: Parsed output:" >&2
  echo "$PARSED" | head -n 30 >&2
  echo "$PARSED"
fi

if $collected_any; then
  echo "]"
else
  echo "[]"
fi
REMOTE
      )

      if [[ "$DEBUG" == true ]]; then
        echo "DEBUG: Collected CRON_INFO raw JSON for $host:" >&2
        echo "$CRON_INFO" | head -n 50 >&2
      fi

      if echo "$CRON_INFO" | jq empty 2>/dev/null; then :; else CRON_INFO="[]"; fi
      RESULTS+=("{\"host\":\"$host\",\"action\":\"collect_cron_jobs\",\"cronJobs\":$CRON_INFO}")
      ;;

    clear_cron_jobs)
      BACKUP_FILE="/var/backups/cronjobs_before_clear.tar.gz"
      RESULT=$(ssh -q root@"$host" "
        mkdir -p /var/backups &&
        tar czf $BACKUP_FILE /etc/cron* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null &&
        find /etc/cron* /var/spool/cron /var/spool/cron/crontabs -type f -exec truncate -s 0 {} + 2>/dev/null &&
        echo 'success' || echo 'failure'
      " 2>/dev/null)
      RESULTS+=("{\"host\":\"$host\",\"action\":\"clear_cron_jobs\",\"result\":\"$RESULT\",\"backup_file\":\"$BACKUP_FILE\"}")
      ;;

    isolate_host)
      CONTROLLING_IP=$(ssh -q root@"$host" "echo \${SSH_CLIENT%% *}" 2>/dev/null)
      RESULT=$(ssh -q root@"$host" "
        iptables-save > /etc/iptables.rules.incident.bak 2>/dev/null || true &&
        iptables -F && iptables -X &&
        iptables -P INPUT DROP && iptables -P FORWARD DROP && iptables -P OUTPUT DROP &&
        iptables -A INPUT -i lo -j ACCEPT &&
        iptables -A OUTPUT -o lo -j ACCEPT &&
        iptables -A INPUT -p tcp --dport 22 -s $CONTROLLING_IP -j ACCEPT &&
        iptables -A OUTPUT -p tcp --sport 22 -d $CONTROLLING_IP -j ACCEPT &&
        echo 'success' || echo 'failure'
      " 2>/dev/null)
      RESULTS+=("{\"host\":\"$host\",\"action\":\"isolate_host\",\"result\":\"$RESULT\"}")
      ;;

    unisolate_host)
      RESULT=$(ssh -q root@"$host" "
        if [ -f /etc/iptables.rules.incident.bak ]; then
          iptables-restore < /etc/iptables.rules.incident.bak 2>/dev/null && echo 'restored' || echo 'restore_failed'
        else
          iptables -F && iptables -X &&
          iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -P OUTPUT ACCEPT &&
          echo 'reset_to_accept'
        fi
      " 2>/dev/null)
      RESULTS+=("{\"host\":\"$host\",\"action\":\"unisolate_host\",\"result\":\"$RESULT\"}")
      ;;

    *)
      RESULTS+=("{\"host\":\"$host\",\"action\":\"$ACTION\",\"result\":\"unsupported_action\"}")
      ;;
  esac
done

# Print final result
DESCRIPTION=$(cat <<EOF
Action: $ACTION
Hosts: $HOSTS
Result:
$( (IFS=,; echo "[${RESULTS[*]}]") | jq . )
EOF
)
echo "$DESCRIPTION"
