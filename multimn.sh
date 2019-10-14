#!/bin/bash
cd ~
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}$0 must be run as root.${NC}"
   exit 1
fi
OS_version=$(cat /etc/lsb-release | grep -c bionic)
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

## Error checks

perl -i -ne 'print if ! $a{$_}++' /etc/network/interfaces

if [ ! -d "/root/bin" ]; then
mkdir /root/bin
fi

## Setup

if [ ! -f "/root/bin/dep" ]
then
  clear
  echo -e "Installing ${GREEN}Cryptocurrency dependencies${NC}. Please wait."
  sleep 2
  apt update 
  apt -y upgrade
  apt update
  sudo add-apt-repository ppa:bitcoin/bitcoin -y && sudo apt-get update && sudo apt-get install libdb4.8-dev libdb4.8++-dev
  
  ## Checking for Swap
  
  if [ ! -f /var/swap.img ]
  then
  echo -e "${RED}Creating swap. This may take a while.${NC}"
  dd if=/dev/zero of=/var/swap.img bs=2048 count=1M
  chmod 600 /var/swap.img
  mkswap /var/swap.img 
  swapon /var/swap.img 
  free -m
  echo "/var/swap.img none swap sw 0 0" >> /etc/fstab
  fi
  
  ufw allow ssh/tcp
  ufw limit ssh/tcp
  ufw logging on
  echo "y" | ufw enable 
  ufw allow 5535
  echo 'export PATH=~/bin:$PATH' > ~/.bash_aliases
  echo ""
  cd
  sysctl vm.swappiness=30
  sysctl vm.vfs_cache_pressure=200
  echo 'vm.swappiness=30' | tee -a /etc/sysctl.conf
  echo 'vm.vfs_cache_pressure=200' | tee -a /etc/sysctl.conf
  touch /root/bin/dep
fi

## Constants

IP4COUNT=$(find /root/.cryptocurrency_* -maxdepth 0 -type d | wc -l)
IP6COUNT=$(crontab -l -u root | wc -l)
DELETED="$(cat /root/bin/deleted | wc -l)"
ALIASES="$(find /root/.cryptocurrency_* -maxdepth 0 -type d | cut -c22-)"
face="$(lshw -C network | grep "logical name:" | sed -e 's/logical name:/logical name: /g' | awk '{print $3}' | head -n1)"
IP4=$(curl -s4 api.ipify.org)
version=$(curl https://raw.githubusercontent.com/CCYofficial/Multi-MN-Script-IPv6/master/current)
link=$(curl https://raw.githubusercontent.com/CCYofficial/Multi-MN-Script-IPv6/master/download)
PORT=5535
RPCPORTT=5536
gateway1=$(/sbin/route -A inet6 | grep -v ^fe80 | grep -v ^ff00 | grep -w "$face")
gateway2=${gateway1:0:26}
gateway3="$(echo -e "${gateway2}" | tr -d '[:space:]')"
if [[ $gateway3 = *"128"* ]]; then
  gateway=${gateway3::-5}
fi
if [[ $gateway3 = *"64"* ]]; then
  gateway=${gateway3::-3}
fi
MASK="/64"

## Systemd Function

function configure_systemd() {
  cat << EOF > /etc/systemd/system/cryptocurrencyd$ALIAS.service
[Unit]
Description=cryptocurrencyd$ALIAS service
After=network.target
 [Service]
User=root
Group=root
Type=forking
#PIDFile=/root/.cryptocurrency_$ALIAS/cryptocurrencyd.pid
ExecStart=/root/bin/cryptocurrencyd_$ALIAS.sh
ExecStop=/root/bin/cryptocurrency-cli_$ALIAS.sh stop
Restart=always
PrivateTmp=true
TimeoutStopSec=60s
TimeoutStartSec=10s
StartLimitInterval=120s
StartLimitBurst=5
 [Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  sleep 2
  echo "sleep 10" >> /root/bin/start_nodes.sh
  echo "systemctl start cryptocurrencyd$ALIAS" >> /root/bin/start_nodes.sh
  chmod +x /root/bin/start_nodes.sh
  systemctl start cryptocurrencyd$ALIAS.service
}

function configure_bashrc() {
	echo "alias ${ALIAS}_status=\"cryptocurrency-cli -datadir=/root/.cryptocurrency_${ALIAS} masternode status\"" >> .bashrc
	echo "alias ${ALIAS}_stop=\"systemctl stop cryptocurrencyd$ALIAS\"" >> .bashrc
	echo "alias ${ALIAS}_start=\"systemctl start cryptocurrencyd$ALIAS\""  >> .bashrc
	echo "alias ${ALIAS}_config=\"nano /root/.cryptocurrency_${ALIAS}/cryptocurrency.conf\""  >> .bashrc
	echo "alias ${ALIAS}_getinfo=\"cryptocurrency-cli -datadir=/root/.cryptocurrency_${ALIAS} getinfo\"" >> .bashrc
	echo "alias ${ALIAS}_getpeerinfo=\"cryptocurrency-cli -datadir=/root/.cryptocurrency_${ALIAS} getpeerinfo\"" >> .bashrc
	echo "alias ${ALIAS}_resync=\"/root/bin/cryptocurrencyd_${ALIAS}.sh -resync\"" >> .bashrc
	echo "alias ${ALIAS}_reindex=\"/root/bin/cryptocurrencyd_${ALIAS}.sh -reindex\"" >> .bashrc
	echo "alias ${ALIAS}_restart=\"systemctl restart cryptocurrencyd$ALIAS\""  >> .bashrc
}

## Check for wallet update

clear

if [ -f "/usr/local/bin/cryptocurrencyd" ]
then

if [ ! -f "/root/bin/$version" ]
then

echo -e "${GREEN}Please wait, updating wallet.${NC}"
sleep 1

mnalias=$(find /root/.cryptocurrency_* -maxdepth 0 -type d | cut -c22- | head -n 1)
PROTOCOL=$(cryptocurrency-cli -datadir=/root/.cryptocurrency_${mnalias} getinfo | grep "protocolversion" | sed 's/[^0-9]*//g')

if [ $PROTOCOL != 71004 ]
then
sed -i 's/22123/5535/g' /root/.cryptocurrency*/cryptocurrency.conf
rm .cryptocurrency*/blocks -rf
rm .cryptocurrency*/chainstate -rf
rm .cryptocurrency*/sporks -rf
rm .cryptocurrency*/zerocoin -rf
fi

wget $link -O /root/cryptocurrency.ubuntu16.04.zip
rm /usr/local/bin/cryptocurrency*
unzip cryptocurrency.ubuntu16.04.zip -d /usr/local/bin 
chmod +x /usr/local/bin/cryptocurrency*
rm cryptocurrency.ubuntu16.04.zip
mkdir /root/bin
touch /root/bin/$version
echo -e "${GREEN}Wallet updated.${NC} ${RED}PLEASE RESTART YOUR NODES OR REBOOT VPS WHEN POSSIBLE.${NC}"
echo ""

fi

fi

## Start of Guided Script
if [ -z $1 ]; then
echo "1 - Create new nodes"
echo "2 - Remove an existing node"
echo "3 - List aliases"
echo "4 - Check node status"
echo "5 - Compile wallet locally"
echo "What would you like to do?"
read DO
echo ""
else
DO=$1
ALIAS=$2
ALIASD=$2
PRIVKEY=$3
fi

if [ $DO = "help" ]
then
echo "Usage:"
echo "./multimn.sh Action Alias PrivateKey"
fi

## List aliases

if [ $DO = "3" ]
then
echo -e "${GREEN}${ALIASES}${NC}"
echo ""
echo "1 - Create new nodes"
echo "2 - Remove an existing node"
echo "4 - Check for node errors"
echo "5 - Compile wallet locally (optional)"
echo "What would you like to do?"
read DO
echo ""
fi

## Compiling wallet

if [ $DO = "5" ]
then
echo -e "${GREEN}Compiling wallet, this may take some time.${NC}"
sleep 2
systemctl stop cryptocurrencyd*

if [ ! -f "/root/bin/depc" ]
then

## Installing pre-requisites

apt install -y zip unzip bc curl nano lshw ufw gawk libdb++-dev git zip automake software-properties-common unzip build-essential libtool autotools-dev autoconf pkg-config libssl-dev libcrypto++-dev libevent-dev libminiupnpc-dev libgmp-dev libboost-all-dev devscripts libsodium-dev libprotobuf-dev protobuf-compiler libcrypto++-dev libminiupnpc-dev gcc-5 g++-5 --auto-remove
thr="$(nproc)"

## Compatibility issues
  
  export LC_CTYPE=en_US.UTF-8
  export LC_ALL=en_US.UTF-8
  apt update
  apt install libssl1.0-dev -y
  apt install libzmq3-dev -y --auto-remove
  update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-5 100
  update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-5 100
  touch /root/bin/depc

fi

## Preparing and building

  git clone https://github.com/CCYofficial/CCY
  cd CCY
  ./autogen.sh
  ./configure --with-incompatible-bdb --disable-tests --without-gui
  make -j $thr
  make install
  touch /root/bin/$version
  
systemctl start cryptocurrencyd*

fi

## Checking for node errors

if [ $DO = "4" ]
then

echo $ALIASES > temp1
cat temp1 | grep -o '[^ |]*' > temp2
CN="$(cat temp2 | wc -l)"
rm temp1
let LOOP=0

while [  $LOOP -lt $CN ]
do

LOOP=$((LOOP+1))
CURRENT="$(sed -n "${LOOP}p" temp2)"

echo -e "${GREEN}${CURRENT}${NC}:"
sh /root/bin/cryptocurrency-cli_${CURRENT}.sh masternode status | grep "message"
done


fi

## Properly Deleting node

if [ $DO = "2" ]
then
if [ -z $1 ]; then
echo "Input the alias of the node that you want to delete"
read ALIASD
fi

echo ""
echo -e "${GREEN}Deleting ${ALIASD}${NC}. Please wait."

## Removing service

systemctl stop cryptocurrencyd$ALIASD >/dev/null 2>&1
systemctl disable cryptocurrencyd$ALIASD >/dev/null 2>&1
rm /etc/systemd/system/cryptocurrencyd${ALIASD}.service >/dev/null 2>&1
systemctl daemon-reload >/dev/null 2>&1
systemctl reset-failed >/dev/null 2>&1
lineNum="$(grep -n "${ALIASD}" bin/start_nodes.sh | head -n 1 | cut -d: -f1)"
lineNum2=$((lineNum+1))

sed -i "${lineNum}d;${lineNum2}d" /root/bin/start_nodes.sh

## Removing node files 

rm /root/.cryptocurrency_$ALIASD -r >/dev/null 2>&1
sed -i "/${ALIASD}/d" .bashrc
crontab -l -u root | grep -v $ALIASD | crontab -u root - >/dev/null 2>&1

source ~/.bashrc
echo "1" >> /root/bin/deleted
rm /root/bin/cryptocurrency*_$ALIASD.sh
echo -e "${ALIASD} Successfully deleted."

fi

## Creating new nodes

if [ $DO = "1" ]
then
MAXC="64"
if [ ! -f "/usr/local/bin/cryptocurrencyd" ]
then
  ## Downloading and installing wallet 
  echo -e "${GREEN}Downloading precompiled wallet${NC}"
  wget $link -O /root/cryptocurrency.ubuntu16.04.zip
  sudo add-apt-repository ppa:bitcoin/bitcoin -y && sudo apt-get update && sudo apt-get install libdb4.8-dev libdb4.8++-dev
  mkdir /root/bin
  touch /root/bin/$version
  unzip cryptocurrency.ubuntu16.04.zip -d /usr/local/bin 
  chmod +x /usr/local/bin/cryptocurrency*
  rm cryptocurrency.ubuntu16.04.zip
  if [ "$OS_version" -eq "1" ]; then
  wget https://github.com/CCYofficial/MN-Script-IPv4/raw/master/libs.zip
  unzip -o libs.zip
  cp -fr libboost_filesystem.so.1.58.0 libboost_chrono.so.1.58.0 libboost_program_options.so.1.58.0 libboost_system.so.1.58.0 libboost_thread.so.1.58.0 libminiupnpc.so.10 libevent_core-2.0.so.5 libevent_pthreads-2.0.so.5 libevent-2.0.so.5 /usr/lib/
  rm -fr libboost_filesystem.so.1.58.0 libboost_chrono.so.1.58.0 libboost_program_options.so.1.58.0 libboost_system.so.1.58.0 libboost_thread.so.1.58.0 libminiupnpc.so.10 libevent_core-2.0.so.5 libevent_pthreads-2.0.so.5 libevent-2.0.so.5 libs.zip
  fi
fi

## Downloading bootstrap

if [ ! -f cryptocurrency-blockchain.zip ]
then
wget https://github.com/CCYofficial/CCY/releases/download/1.1.0.0/cryptocurrency-blockchain.zip -O /root/cryptocurrency-blockchain.zip
fi

## Start of node creation

echo -e "Cryptocurrency nodes currently installed: ${GREEN}${IP4COUNT}${NC}, Cryptocurrency nodes previously Deleted: ${GREEN}${DELETED}${NC}"
echo ""


if [ $IP4COUNT = "0" ] 
then

echo -e "${RED}First node must be ipv4.${NC}"
let COUNTER=0
RPCPORT=$(($RPCPORTT+$COUNTER))
  if [ -z $1 ]; then
  echo ""
  echo "Enter alias for first node"
  read ALIAS
  echo ""
  echo "Enter masternode private key for node $ALIAS"
  read PRIVKEY
  fi
  CONF_DIR=/root/.cryptocurrency_$ALIAS
  
  mkdir /root/.cryptocurrency_$ALIAS
  unzip cryptocurrency-blockchain.zip -d /root/.cryptocurrency_$ALIAS >/dev/null 2>&1
  echo '#!/bin/bash' > ~/bin/cryptocurrencyd_$ALIAS.sh
  echo "cryptocurrencyd -daemon -conf=$CONF_DIR/cryptocurrency.conf -datadir=$CONF_DIR "'$*' >> ~/bin/cryptocurrencyd_$ALIAS.sh
  echo '#!/bin/bash' > ~/bin/cryptocurrency-cli_$ALIAS.sh
  echo "cryptocurrency-cli -conf=$CONF_DIR/cryptocurrency.conf -datadir=$CONF_DIR "'$*' >> ~/bin/cryptocurrency-cli_$ALIAS.sh
  echo '#!/bin/bash' > ~/bin/cryptocurrency-tx_$ALIAS.sh
  echo "cryptocurrency-tx -conf=$CONF_DIR/cryptocurrency.conf -datadir=$CONF_DIR "'$*' >> ~/bin/cryptocurrency-tx_$ALIAS.sh
  chmod 755 ~/bin/cryptocurrency*.sh

  echo "rpcuser=user"`shuf -i 100000-10000000 -n 1` >> cryptocurrency.conf_TEMP
  echo "rpcpassword=pass"`shuf -i 100000-10000000 -n 1` >> cryptocurrency.conf_TEMP
  echo "rpcallowip=127.0.0.1" >> cryptocurrency.conf_TEMP
  echo "rpcport=$RPCPORT" >> cryptocurrency.conf_TEMP
  echo "listen=1" >> cryptocurrency.conf_TEMP
  echo "server=1" >> cryptocurrency.conf_TEMP
  echo "daemon=1" >> cryptocurrency.conf_TEMP
  echo "logtimestamps=1" >> cryptocurrency.conf_TEMP
  echo "maxconnections=$MAXC" >> cryptocurrency.conf_TEMP
  echo "masternode=1" >> cryptocurrency.conf_TEMP
  echo "" >> cryptocurrency.conf_TEMP
  echo "" >> cryptocurrency.conf_TEMP
  echo "bind=$IP4:$PORT" >> cryptocurrency.conf_TEMP
  echo "externalip=$IP4" >> cryptocurrency.conf_TEMP
  echo "masternodeaddr=$IP4:$PORT" >> cryptocurrency.conf_TEMP
  echo "masternodeprivkey=$PRIVKEY" >> cryptocurrency.conf_TEMP
  
  mv cryptocurrency.conf_TEMP $CONF_DIR/cryptocurrency.conf
  
  crontab -l > cron$ALIAS
  echo "@reboot sh /root/bin/start_nodes.sh" >> cron$ALIAS
  crontab cron$ALIAS
  rm cron$ALIAS
  echo ""
  echo -e "Your ip is ${GREEN}$IP4:$PORT${NC}"
  
	## Setting up .bashrc
	configure_bashrc
	## Creating systemd service
	configure_systemd
fi

if [ $IP4COUNT != "0" ] 
then
if [ -z $1 ]; then
echo "How many ipv6 nodes do you want to install on this server?"
read MNCOUNT
else
MNCOUNT=1
fi

## This can probably be shortened but whatever

let MNCOUNT=MNCOUNT+1
let MNCOUNT=MNCOUNT+IP4COUNT
let MNCOUNT=MNCOUNT+DELETED
let COUNTER=1
let COUNTER=COUNTER+IP4COUNT
let COUNTER=COUNTER+DELETED

while [  $COUNTER -lt $MNCOUNT ]
do
  RPCPORT=$(($RPCPORTT+$COUNTER))
  
  if [ -z $1 ]; then
  echo ""
  echo "Enter alias for new node"
  read ALIAS
  echo ""
  echo "Enter masternode private key for node $ALIAS"
  read PRIVKEY
  fi
  
  CONF_DIR=/root/.cryptocurrency_$ALIAS
  /sbin/ip -6 addr add ${gateway}$COUNTER$MASK dev $face
  mkdir /root/.cryptocurrency_$ALIAS
  
  unzip cryptocurrency-blockchain.zip -d ~/.cryptocurrency_$ALIAS >/dev/null 2>&1
  echo '#!/bin/bash' > ~/bin/cryptocurrencyd_$ALIAS.sh
  echo "cryptocurrencyd -daemon -conf=$CONF_DIR/cryptocurrency.conf -datadir=$CONF_DIR "'$*' >> ~/bin/cryptocurrencyd_$ALIAS.sh
  echo '#!/bin/bash' > ~/bin/cryptocurrency-cli_$ALIAS.sh
  echo "cryptocurrency-cli -conf=$CONF_DIR/cryptocurrency.conf -datadir=$CONF_DIR "'$*' >> ~/bin/cryptocurrency-cli_$ALIAS.sh
  echo '#!/bin/bash' > ~/bin/cryptocurrency-tx_$ALIAS.sh
  echo "cryptocurrency-tx -conf=$CONF_DIR/cryptocurrency.conf -datadir=$CONF_DIR "'$*' >> ~/bin/cryptocurrency-tx_$ALIAS.sh
  chmod 755 ~/bin/cryptocurrency*.sh
  
  echo "rpcuser=user"`shuf -i 100000-10000000 -n 1` >> cryptocurrency.conf_TEMP
  echo "rpcpassword=pass"`shuf -i 100000-10000000 -n 1` >> cryptocurrency.conf_TEMP
  echo "rpcallowip=127.0.0.1" >> cryptocurrency.conf_TEMP
  echo "rpcport=$RPCPORT" >> cryptocurrency.conf_TEMP
  echo "listen=1" >> cryptocurrency.conf_TEMP
  echo "server=1" >> cryptocurrency.conf_TEMP
  echo "daemon=1" >> cryptocurrency.conf_TEMP
  echo "logtimestamps=1" >> cryptocurrency.conf_TEMP
  echo "maxconnections=$MAXC" >> cryptocurrency.conf_TEMP
  echo "masternode=1" >> cryptocurrency.conf_TEMP
  echo "bind=[${gateway}$COUNTER]:$PORT" >> cryptocurrency.conf_TEMP
  echo "externalip=[${gateway}$COUNTER]" >> cryptocurrency.conf_TEMP
  echo "masternodeaddr=[${gateway}$COUNTER]:$PORT" >> cryptocurrency.conf_TEMP
  echo "masternodeprivkey=$PRIVKEY" >> cryptocurrency.conf_TEMP
  mv cryptocurrency.conf_TEMP $CONF_DIR/cryptocurrency.conf
  
  crontab -l -u root | grep -v start_nodes.sh | crontab -u root -
  crontab -l > cron$ALIAS
  echo "@reboot /sbin/ip -6 addr add ${gateway}$COUNTER$MASK dev $face # $ALIAS" >> cron$ALIAS
  crontab cron$ALIAS
  rm cron$ALIAS
  crontab -l > cron$ALIAS
  echo "@reboot sh /root/bin/start_nodes.sh" >> cron$ALIAS
  crontab cron$ALIAS
  rm cron$ALIAS
  
  echo ""
  echo -e "Your ip is ${GREEN}[${gateway}$COUNTER]:$PORT${NC}"
  
	## Setting up .bashrc
	configure_bashrc
	## Creating systemd service
	configure_systemd
	COUNTER=$((COUNTER+1))
	
done

fi

echo ""
echo "Commands:"
echo "${ALIAS}_start"
echo "${ALIAS}_restart"
echo "${ALIAS}_status"
echo "${ALIAS}_stop"
echo "${ALIAS}_config"
echo "${ALIAS}_getinfo"
echo "${ALIAS}_getpeerinfo"
echo "${ALIAS}_resync"
echo "${ALIAS}_reindex"
fi

echo ""

source ~/.bashrc
