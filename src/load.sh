# unload
sudo ./xdp_loader --unload --dev enp2s0 --skb-mode
sudo rm -R /sys/fs/bpf/enp2s0/xdp_stats_map
sudo rm -R /sys/fs/bpf/enp2s0/mapall
sudo rm -R /sys/fs/bpf/enp2s0/tdiff

# load
sudo ./xdp_loader --dev enp2s0 --skb-mode

# listener uspace
# sudo ./xpro_uspace
