#network config
INTERFACE="eth1"
IP="192.168.1.5"

#SSL Listening Port for decrypt
SSL="443"

#dnschef config
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

#setup firewall routing rules
sudo sysctl net.ipv4.ip_forward=1
sudo iptables -t nat -F
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport $SSL -j DNAT --to-destination $IP:10443
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --match multiport --dport 1:65535 -j DNAT --to-destination $IP:10000
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p udp --match multiport --dport 1:52,54:65535 -j DNAT --to-destination $IP:20000

#setup dns server
sudo pkill -f dnschef
sudo rm dnslog.txt
(sudo dnschef -i $IP --fakeip $IP --file sinkhole.txt --logfile dnslog.txt -q > /dev/null 2>&1 &)
sleep 1s
#setup tmux windows and listeners
tmux kill-session -t listeningpost
tmux new-session -d -s listeningpost -x "$(tput cols)" -y "$(tput lines)"
tmux set -g pane-border-status top
tmux select-pane -T DNSLOG
tmux send 'tail -F dnslog.txt | grep '"$IP" ENTER
tmux split-window -p 75
tmux select-pane -T SSLPROXY-$SSL
#Note: copy ~/.mitmproxy/mitmproxy-ca.pem to windows, run certutil -addstore root mitmproxy-ca.pem
tmux send 'mitmproxy --mode reverse:http://'"$IP"':10000 --listen-port 10443 --listen-host '"$IP" ENTER
tmux split-window -p 70
tmux select-pane -T LISTENER
tmux send 'socat tcp-listen:10000,fork,reuseaddr stdout' ENTER
tmux a
