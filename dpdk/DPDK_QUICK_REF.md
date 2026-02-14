# DPDK Quick Reference Card

## Essential Commands Cheat Sheet

### Setup (One-time)

```bash
# 1. Install huge pages
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

# 2. Load DPDK driver
sudo modprobe vfio-pci

# 3. Bind NIC to DPDK
sudo dpdk-devbind.py --bind=vfio-pci ens3
```

### Build

```bash
# Meson (recommended)
meson setup build && cd build && ninja

# OR pkg-config
gcc -O3 $(pkg-config --cflags libdpdk glib-2.0) \
    main_dpdk.c quic_d_optimized.c \
    $(pkg-config --libs libdpdk glib-2.0) \
    -lgcrypt -lssl -lcrypto -o quic_decrypt_dpdk
```

### Run

```bash
# Basic (4 cores)
sudo ./quic_decrypt_dpdk -l 0-3 -n 4 --

# High performance (16 cores)
sudo ./quic_decrypt_dpdk -l 0-15 -n 4 --socket-mem=2048,2048 --

# Single core (testing)
sudo ./quic_decrypt_dpdk -l 0-1 -n 4 --
```

### Cleanup

```bash
# Unbind from DPDK
sudo dpdk-devbind.py --unbind 0000:02:00.0

# Bind back to kernel
sudo dpdk-devbind.py --bind=i40e 0000:02:00.0
sudo ip link set ens3 up
```

### Monitoring

```bash
# Check huge pages
cat /proc/meminfo | grep Huge

# Check bound devices
dpdk-devbind.py --status

# Monitor CPU performance
sudo perf top

# Check interrupts
watch -n 1 cat /proc/interrupts
```

### Troubleshooting

```bash
# No ports available?
dpdk-devbind.py --status
sudo dpdk-devbind.py --bind=vfio-pci ens3

# Out of memory?
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Permission denied?
sudo ./quic_decrypt_dpdk ...

# Low performance?
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

## EAL Parameter Reference

| Parameter       | Description          | Example                  |
| --------------- | -------------------- | ------------------------ |
| `-l`            | CPU cores            | `-l 0-3` or `-l 0,2,4`   |
| `-n`            | Memory channels      | `-n 4`                   |
| `-m`            | Memory limit (MB)    | `-m 1024`                |
| `--socket-mem`  | Memory per NUMA      | `--socket-mem=1024,1024` |
| `--log-level`   | Verbosity (0-8)      | `--log-level=8`          |
| `--proc-type`   | Process type         | `--proc-type=primary`    |
| `--file-prefix` | Shared memory prefix | `--file-prefix=quic`     |

## Performance Matrix

| Setup           | Expected Throughput |
| --------------- | ------------------- |
| 1 worker core   | 2-5 Mpps            |
| 4 worker cores  | 8-15 Mpps           |
| 8 worker cores  | 15-30 Mpps          |
| 16 worker cores | 25-50 Mpps          |

## Common Issues

| Problem                   | Solution                        |
| ------------------------- | ------------------------------- |
| "cannot init EAL"         | Check huge pages allocation     |
| "No Ethernet ports"       | Bind NIC to DPDK driver         |
| "Cannot create mbuf pool" | Increase huge pages             |
| "Permission denied"       | Run with sudo                   |
| Low performance           | Set CPU governor to performance |

## File Structure

```
quic_decrypt_dpdk/
├── main_dpdk.c          # DPDK main program
├── quic_d_optimized.c   # Crypto functions
├── quic_d.h             # Header file
├── meson_dpdk.build     # Meson build file
├── Makefile.dpdk        # Traditional Makefile
└── DPDK_GUIDE.md        # Full documentation
```

## Comparison Snapshot

| Feature     | libpcap  | DPDK       |
| ----------- | -------- | ---------- |
| Speed       | 100K pps | 10M+ pps   |
| Setup       | Easy     | Complex    |
| Scalability | Poor     | Excellent  |
| Best for    | Dev/Test | Production |
