# unload
sudo ./xdp_loader --unload --dev ens3 --skb-mode
sudo rm -R /sys/fs/bpf/ens3/xdp_stats_map
sudo rm -R /sys/fs/bpf/ens3/mapall

# load
sudo ./xdp_loader --dev ens3 --skb-mode

# listener uspace
# sudo ./xpro_uspace
