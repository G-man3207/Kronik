#!/usr/bin/env bash
# Records the test host: OS, kernel, CPU, memory, disk, KVM, cgroups, docker
# and the installed gVisor release.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record 01-survey

section "OS and kernel"
grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
uname -srvm

section "CPU and memory"
nproc
lscpu | grep -E '^(Model name|Hypervisor vendor|Virtualization type|Flags)' | cut -c1-120
echo "vmx/svm flags: $(grep -cE 'vmx|svm' /proc/cpuinfo)"
free -h

section "Disk"
df -h / /run

section "KVM"
ls -l /dev/kvm 2>&1

section "cgroups"
stat -fc 'filesystem: %T' /sys/fs/cgroup
echo "controllers: $(cat /sys/fs/cgroup/cgroup.controllers)"
mount | grep cgroup
systemctl --version | head -1

section "Docker (present, not used by the spike)"
docker version --format 'server {{.Server.Version}}' 2>&1

section "gVisor"
show runsc --version
ls -l /usr/local/bin/runsc /usr/local/bin/gvisor-bin/
