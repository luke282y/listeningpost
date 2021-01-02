#network config
INTERFACE="eth1"
IP="192.168.1.5"

#SSL Listening Port for decrypt
SSL="443"

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
sudo iptables -t raw -A PREROUTING -i $INTERFACE -j LOG
USER=$(whoami)
sudo setfacl -m u:$USER:r /var/log/syslog
sudo truncate -s 0 /var/log/syslog

#setup dns server
sudo pkill -f dnschef
sudo rm dnslog.txt
(sudo dnschef -i $IP --fakeip $IP --file sinkhole.txt --logfile dnslog.txt -q > /dev/null 2>&1 &)
sleep 1s

#setup tmux windows and listeners
tmux kill-session -t listeningpost
tmux new-session -d -s listeningpost -x "$(tput cols)" -y "$(tput lines)"
tmux set -g pane-border-status top
tmux select-pane -T DNS_LOG
tmux send 'tail -F dnslog.txt | grep "\sfor.*\sto\s'"$IP"'"' ENTER
tmux split-window -p 80
tmux select-pane -T FIREWALL_LOG
tmux send 'tail -F /var/log/syslog | grep -oP "SRC=.*\sDST.*PROTO=\w\w\w\sSPT=\d+\sDPT=\d+" | grep -P "PROTO=\w\w\w\sSPT=\d+\sDPT=\d+"' ENTER
tmux split-window -p 80
tmux select-pane -T SSLPROXY-$SSL
#Note: copy ~/.mitmproxy/mitmproxy-ca.pem to windows, run certutil -addstore root mitmproxy-ca-cert.pem
tmux send 'mitmproxy --mode reverse:http://'"$IP"':10000 --listen-port 10443 --listen-host '"$IP" ENTER
tmux split-window -p 70 
tmux select-pane -T TCP-LISTENER
tmux send 'socat -v tcp-listen:10000,fork,reuseaddr stdout' ENTER
tmux split-window -h -p 50
tmux select-pane -T UDP-LISTENER
tmux send 'socat -v udp-listen:20000,fork,reuseaddr stdout' ENTER
tmux select-pane -t 3
tmux a
