#Listeningpost will configure a Kali OS host as a malware listener
#Client machine should have DNS and default gateway set to IP configured in IP variable
#DNSchef is started on UDP port 53 with the specified black list of domains to resolv to localhost
#All incoming traffic on the configured interface will be forwarded to the specified local IP address
#ALL TCP ports are forwarded to TCP PORT 10000 and UDP ports (except 53) are forwarded to UDP 20000
#The configured HTTPS port (443 by default) is forwared to port 10443 where mitmproxy is listening
#mitmproxy will decrypt HTTPS traffic and send it to TCP port 10000
#copy ~/.mitmproxy/mitmproxy-ca-cert.cer to windows, run certutil -addstore root mitmproxy-ca-cert.cer
#A tmux session will be created with DNS, Firewall Forwarding, HTTPS proxy, and TCP/UDP socat listeners

#network config
INTERFACE="eth1"
IP="192.168.6.10"

#SSL Listening Port for decrypt
SSL="443"

#path to tcpdump, this may change depending on version of kali
#you can find the path with the commad which tcpdump
TCPDUMP_PATH="/usr/bin/tcpdump"

#dnschef config,blacklist domains
cat > sinkhole.txt << EOF1
[A]
config.edge.skype.com:127.0.0.1
config.teams.microsoft.com:127.0.0.1
ctldl.windowsupdate.com:127.0.0.1
dns.msftncsi.com:127.0.0.1
download.wireguard.com:127.0.0.1
iecvlist.microsoft.com:127.0.0.1
ocsp.digicert.com:127.0.0.1
settings-win.data.microsoft.com:127.0.0.1
slscr.update.microsoft.com:127.0.0.1
watson.telemetry.microsoft.com:127.0.0.1
www.bing.com:127.0.0.1
g.live.com:127.0.0.1
v10.events.data.microsoft.com:127.0.0.1

[PTR]
*:127.0.0.1
EOF1

#remove any old firewall rules
sudo iptables -t nat -F
sudo iptables -F
#setup firewall routing rules
sudo sysctl net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport $SSL -j DNAT --to-destination $IP:10443
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --match multiport --dport 1:65535 -j DNAT --to-destination $IP:10000
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p udp --match multiport --dport 1:52,54:65535 -j DNAT --to-destination $IP:20000
#setup firewall logging
sudo modprobe ipt_LOG
sudo iptables -t raw -A PREROUTING -i $INTERFACE -p tcp -j LOG
sudo iptables -t raw -A PREROUTING -i $INTERFACE -p udp -j LOG
sudo truncate -s 0 /var/log/syslog

#setup dns server
sudo pkill -f dnschef
sudo rm dnslog.txt
(sudo dnschef -i $IP --fakeip $IP --file sinkhole.txt --logfile dnslog.txt -q > /dev/null 2>&1 &)
sleep 1s

#fix permissions to run as non-root
USER=$(whoami)
sudo groupadd listeningpost
sudo usermod -a -G listeningpost $USER
sudo chgrp listeningpost $TCPDUMP_PATH
sudo chmod 750 $TCPDUMP_PATH
sudo setcap cap_net_raw,cap_net_admin=eip $TCPDUMP_PATH

#save user tmux conf and enable mouse
cp ~/.tmux.conf ~/.tmux.conf.bak
echo "set -g mouse on" >> ~/.tmux.conf
#setup tmux windows and listeners
tmux kill-session -t listeningpost
tmux new-session -d -s listeningpost -x "$(tput cols)" -y "$(tput lines)"
tmux set -g pane-border-status top
#pane 0 - DNS LOG
tmux select-pane -T DNS-LOG
tmux send 'tail -F dnslog.txt | grep "\sfor.*\sto\s'"$IP"'"' ENTER
tmux send-keys -R
#pane 1 - TCP Connections
tmux split-window -p 80
tmux select-pane -T TCP-CONNECTIONS
tmux send 'tcpdump -q -n -l -i '"$INTERFACE"' -Q in "tcp[tcpflags] & (tcp-syn) !=0 and tcp[tcpflags] & (tcp-ack) =0" 2>/dev/null' ENTER
tmux send-keys -R
#pane 4 SSL Proxy
tmux split-window -p 80
tmux select-pane -T HTTPS-PROXY-$SSL
#Note: copy ~/.mitmproxy/mitmproxy-ca-cert.cer to windows, run certutil -addstore root mitmproxy-ca-cert.cer
tmux send 'mitmproxy -v --showhost --rawtcp --mode reverse:http://'"$IP"':10000 --listen-port 10443 --listen-host '"$IP" ENTER
tmux send-keys -R
#pane 3 UDP Connections
tmux select-pane -t 1
tmux split-window -h -p 50
tmux select-pane -T UDP-CONNECTIONS
tmux send 'tcpdump -q -n udp -i '"$INTERFACE"' -Q in dst port not 53 2>/dev/null' ENTER
tmux send-keys -R
#pane 5 TPC Listener
tmux select-pane -t 3
tmux split-window -p 70 
tmux select-pane -T TCP-LISTENER
tmux send 'socat -v tcp-listen:10000,fork,reuseaddr stdout' ENTER
tmux send-keys -R
#pane 6 UPD Listener
tmux split-window -h -p 50
tmux select-pane -T UDP-LISTENER
tmux send 'socat -v udp-listen:20000,fork,reuseaddr stdout' ENTER
tmux send-keys -R
#pane 7 Shell pre populated with kill command
tmux split-window -p 20
tmux select-pane -T SHELL
tmux send 'tmux kill-session -t listeningpost'
tmux send-keys -R
#open new windows with full tcp dump
tmux new-window 
tmux send 'tcpdump -nnXSs 0 -i '"$INTERFACE"' host '"$IP" ENTER
tmux send-keys -R
tmux select-window -t 0
tmux a
#restore old user tmux conf
mv ~/.tmux.conf.bak ~/.tmux.conf
