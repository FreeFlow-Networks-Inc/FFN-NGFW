#!/bin/bash
echo "=== All PCIe devices ==="
lspci -nn | head -40
echo ""
echo "=== lspci -tree ==="
lspci -t -v | head -40
echo ""
echo "=== dmesg — PCIe related ==="
dmesg | grep -Ei 'pci.*(xilinx|bittware|link down|link up|Unsupported)' | tail -30
echo ""
echo "=== dmesg — errors ==="
dmesg | grep -iE 'error|fail' | tail -20
echo ""
echo "=== lspci -v | Xilinx / FPGA nearby ==="
lspci -v 2>/dev/null | grep -B2 -A10 -Ei 'xilinx|fpga|altera|bittware' | head -40
echo ""
echo "=== /sys/bus/pci re-scan test (non-destructive) ==="
ls /sys/bus/pci/rescan 2>/dev/null && echo "  rescan available"
echo ""
echo "=== dmidecode PCIe slots ==="
command -v dmidecode >/dev/null && dmidecode -t slot 2>/dev/null | head -60 || echo "  no dmidecode"
echo ""
echo "=== Any xdma/xocl/vfio kernel modules available in /lib/modules? ==="
find /lib/modules/$(uname -r) -name 'xdma*' -o -name 'xocl*' -o -name 'vfio-pci*' 2>/dev/null | head -10
echo ""
echo "=== USB JTAG cable present? (if you program via JTAG) ==="
lsusb | grep -iE 'xilinx|digilent|ftdi' | head -5 || echo "  no JTAG cable detected"
echo ""
echo "=== PCI slot power / link status for slot 0000:19:00 (your NICs) ==="
lspci -s 19:00.0 -vv 2>/dev/null | grep -E 'LnkSta|LnkCap|SltSta' | head -10
