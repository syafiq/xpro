sudo ./xdp_loader --unload --dev lo --skb-mode
sudo rm -R /sys/fs/bpf/lo/xdp_stats_map
sudo rm -R /sys/fs/bpf/lo/ts1
sudo rm -R /sys/fs/bpf/lo/ts2
sudo rm -R /sys/fs/bpf/lo/counter_c
