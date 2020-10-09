sudo ./xdp_loader --unload --dev enp2s0 --skb-mode
sudo rm -R /sys/fs/bpf/enp2s0/xdp_stats_map
sudo rm -R /sys/fs/bpf/enp2s0/mapall
sudo rm -R /sys/fs/bpf/enp2s0/tdiff
sudo rm -R /sys/fs/bpf/enp2s0/stats
