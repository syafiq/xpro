sudo ./xdp_loader --unload --dev enp0s10 --skb-mode
sudo rm -R /sys/fs/bpf/enp010/xdp_stats_map
sudo rm -R /sys/fs/bpf/enp0s10/ts1
sudo rm -R /sys/fs/bpf/enp0s10/ts2
sudo rm -R /sys/fs/bpf/enp0s10/counter_c
