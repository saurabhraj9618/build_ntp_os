#!/bin/bash

# Debian Live ISO script
#

set -e

# Install needed packages for default build
apt-get -y install xorriso live-build syslinux squashfs-tools python-docutils

# Install needed packages for the choose your own kernel option
apt-get -y install wget fakeroot gcc libncurses5-dev bc \
ca-certificates pkg-config make flex bison build-essential autoconf \
automake aptitude
