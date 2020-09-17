sudo ./xdp_loader --unload --dev ens3 --skb-mode
sudo rm -R /sys/fs/bpf/ens3/xdp_stats_map
sudo rm -R /sys/fs/bpf/ens3/mapall
