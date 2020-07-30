sudo ./xdp_loader --unload --dev enp0s10 --skb-mode
sudo rm -R /sys/fs/bpf/enp0s10/xdp_stats_map
sudo rm -R /sys/fs/bpf/enp0s10/ts1
sudo rm -R /sys/fs/bpf/enp0s10/ts2
sudo rm -R /sys/fs/bpf/enp0s10/counter_c
sudo rm -R /sys/fs/bpf/enp0s10/mark
sudo rm -R /sys/fs/bpf/enp0s10/diffcount_dc
sudo rm -R /sys/fs/bpf/enp0s10/ts1_star
sudo rm -R /sys/fs/bpf/enp0s10/ts2_star
sudo rm -R /sys/fs/bpf/enp0s10/c_star
