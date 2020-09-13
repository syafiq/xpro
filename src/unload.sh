sudo ./xdp_loader --unload --dev enp0s8 --skb-mode
sudo rm -R /sys/fs/bpf/enp0s8/xdp_stats_map
sudo rm -R /sys/fs/bpf/enp0s8/ts1
sudo rm -R /sys/fs/bpf/enp0s8/ts2
sudo rm -R /sys/fs/bpf/enp0s8/counter_c
sudo rm -R /sys/fs/bpf/enp0s8/mark
sudo rm -R /sys/fs/bpf/enp0s8/diffcount_dc
sudo rm -R /sys/fs/bpf/enp0s8/ts1_star
sudo rm -R /sys/fs/bpf/enp0s8/ts2_star
sudo rm -R /sys/fs/bpf/enp0s8/c_star
