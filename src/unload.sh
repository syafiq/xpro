sudo ./xdp_loader --unload --dev ens3 --skb-mode
sudo rm -R /sys/fs/bpf/ens3/xdp_stats_map
sudo rm -R /sys/fs/bpf/ens3/ts1
sudo rm -R /sys/fs/bpf/ens3/ts2
sudo rm -R /sys/fs/bpf/ens3/counter_c
sudo rm -R /sys/fs/bpf/ens3/mark
sudo rm -R /sys/fs/bpf/ens3/diffcount_dc
sudo rm -R /sys/fs/bpf/ens3/ts1_star
sudo rm -R /sys/fs/bpf/ens3/ts2_star
sudo rm -R /sys/fs/bpf/ens3/c_star
