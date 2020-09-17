sudo ./xdp_loader --unload --dev ens3 --skb-mode
sudo rm -R /sys/fs/bpf/ens3/xdp_stats_map
sudo rm -R /sys/fs/bpf/ens3/mapall
sudo rm -R /sys/fs/bpf/ens3/ts1_star
sudo rm -R /sys/fs/bpf/ens3/ts2_star
sudo rm -R /sys/fs/bpf/ens3/c_star
