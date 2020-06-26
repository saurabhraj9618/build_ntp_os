#!/bin/bash
dpkg -i dkms_*
dpkg -i pfring_*
dpkg -i pfring-dkms*
dpkg -i ixgbe*
dpkg -i igb*
dpkg -i e100*
dpkg -i fm10k*
dpkg -i i40e*
dpkg -i pfring-drivers*
mkdir -p /usr/local/bin/probe
cp vnfs_balance /usr/local/bin/probe/
chmod 777 /usr/local/bin/probe/vnfs_balance
cp pf_ringctl /usr/local/bin/
chmod 755 /usr/local/bin/pf_ringctl
