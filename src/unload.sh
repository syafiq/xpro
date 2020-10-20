sudo ./xdp_loader --unload --dev ens10 --skb-mode
sudo rm -R /sys/fs/bpf/ens10/xdp_stats_map
sudo rm -R /sys/fs/bpf/ens10/mapall
sudo rm -R /sys/fs/bpf/ens10/tdiff
sudo rm -R /sys/fs/bpf/ens10/stats
