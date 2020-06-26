#!/bin/bash

# Copyright Vehere
# All rights reserved
# Debian Live/Install ISO script
#
# Please RUN ON Debian Stretch only !!!

set -e

usage()
{
cat << EOF

usage: $0 options

###################################
#!!! RUN on Debian Stretch ONLY !!!#
###################################

VNFS build your own ISO options

OPTIONS:
   -h      Help info
   -g      GUI option - can be "no-desktop"
   -p      Add package(s) to the build - can be one-package or "package1 package2 package3...." (should be confined to up to 10 packages)
   -k      Kernel option - can be the stable standard version of the kernel you wish to deploy - 
           aka you can choose any kernel "3.x.x" you want.
           Example: "3.10" or "3.19.6" or "3.18.11" 
           
           More info on kernel versions and support:
           https://www.kernel.org/
           https://www.kernel.org/category/releases.html
           
   By default no options are required. The options presented here are if you wish to enable/disable/add components.
   By default VNFS will be build with a standard Debian Stretch 64 bit distro and kernel ver 3.16.
   
   EXAMPLE (default): 
   ./build-debian-live.sh 
   The example above (is the default) will build a VNFS standard Debian Stretch 64 bit distro (with kernel ver 3.16)
   
   EXAMPLE (customizations): 
   
   ./build-debian-live.sh -k 3.19.6 
   The example above will build a VNFS Debian Stretch 64 bit distro with kernel ver 3.19.6
   
   ./build-debian-live.sh -k 3.18.11 -p one-package
   The example above will build a VNFS Debian Stretch 64 bit distro with kernel ver 3.18.11
   and add the extra package named  "one-package" to the build.
   
   ./build-debian-live.sh -k 3.18.11 -g no-desktop -p one-package
   The example above will build a VNFS Debian Stretch 64 bit distro, no desktop with kernel ver 3.18.11
   and add the extra package named  "one-package" to the build.
   
   ./build-debian-live.sh -k 3.18.11 -g no-desktop -p "package1 package2 package3"
   The example above will build a VNFS Debian Stretch 64 bit distro, no desktop with kernel ver 3.18.11
   and add the extra packages named  "package1", "package2", "package3" to the build.
   
   
   
EOF
}

GUI=
KERNEL_VER=

while getopts “hg:k:p:” OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         g)
             GUI=$OPTARG
             if [[ "$GUI" != "no-desktop" ]]; 
             then
               echo -e "\n Please check the option's spelling \n"
               usage
               exit 1;
             fi
             ;;
         k)
             KERNEL_VER=$OPTARG
             if [[ "$KERNEL_VER" =~ ^[3-4]\.[0-9]+?\.?[0-9]+$ ]];
             then
               echo -e "\n Kernel version set to ${KERNEL_VER} \n"
             else
               echo -e "\n Please check the option's spelling "
               echo -e " Also - only kernel versions >3.0 are supported !! \n"
               usage
               exit 1;
             fi
             ;;
         p)
             PKG_ADD+=("$OPTARG")
             #echo "The first value of the pkg array 'PKG_ADD' is '$PKG_ADD'"
             #echo "The whole list of values is '${PKG_ADD[@]}'"
             echo "Packages to be added to the build: ${PKG_ADD[@]} "
             #exit 1;
             ;;
         ?)
             GUI=
             KERNEL_VER=
             PKG_ADD=
             echo -e "\n Using the default options for the VNFS ISO build \n"
             ;;
     esac
done
shift $((OPTIND -1))

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Begin
# Pre staging
#

mkdir -p VNFS-Live-Build

if [[ -n "$KERNEL_VER" ]]; 
then 
  
  ### START Kernel Version choice ###
  
  cd VNFS-Live-Build && mkdir -p kernel-misc && cd kernel-misc 
#  if [[ ${KERNEL_VER} == 3* ]];
#  then 
#    wget https://www.kernel.org/pub/linux/kernel/v3.x/linux-${KERNEL_VER}.tar.xz
#  elif [[ ${KERNEL_VER} == 4* ]];
#  then
#     wget https://www.kernel.org/pub/linux/kernel/v4.x/linux-${KERNEL_VER}.tar.xz
#  else
#    echo "Unsupported kernel version! Only kernel >3.0 are supported"
#    exit 1;
#  fi
#
#  if [ $? -eq 0 ];
#  then
#    echo -e "Downloaded successfully linux-${KERNEL_VER}.tar.xz "
#  else
#    echo -e "\n Please check your connection \n"
#    echo -e "CAN NOT download the requested kernel. Please make sure the kernel version is present here - \n"
#    echo -e "https://www.kernel.org/pub/linux/kernel/v3.x/ \n"
#    echo -e "or here respectively \n"
#    echo -e "https://www.kernel.org/pub/linux/kernel/v4.x/ \n"
#    exit 1;
#  fi
  cp ../../linux-${KERNEL_VER}.tar.xz . 
  tar xfJ linux-${KERNEL_VER}.tar.xz 
  cd linux-${KERNEL_VER}
  
  # cp /boot/config-4.9.0-6-amd64 .config
  # Default linux kernel config
  # Set up concurrent jobs with respect to number of CPUs
  
  make defconfig && \
  make clean && \
  make -j `getconf _NPROCESSORS_ONLN` deb-pkg LOCALVERSION=-amd64 KDEB_PKGVERSION=4.9.0-6
  cd ../../
  
  # Directory where the kernel image and headers are copied to
  mkdir -p config/packages.chroot/
  # Directory that needs to be present for the Kernel Version choice to work
  mkdir -p cache/contents.chroot/
  # Hook directory for the initramfs script to be copied to
  mkdir -p config/hooks/normal/
  
  # Copy the kernel image and headers
  mv kernel-misc/*.deb config/packages.chroot/
  cp ../staging/config/hooks/all_chroot_update-initramfs.sh config/hooks/normal/all_chroot_update-initramfs.chroot
    
  
  ### END Kernel Version choice ### 
  
  lb config \
  -a amd64 -d stretch  \
  --archive-areas "main contrib" \
  --swap-file-size 2048 \
  --bootloader syslinux \
  --debian-installer live \
  --bootappend-live "boot=live swap config username=vehere live-config.hostname=VNFS live-config.user-default-groups=audio,cdrom,floppy,video,dip,plugdev,scanner,bluetooth,netdev,sudo" \
  --linux-packages linux-image-${KERNEL_VER} \
  --linux-packages linux-headers-${KERNEL_VER} \
  --apt-options "--yes --force-yes" \
  --linux-flavour amd64 \
  --iso-application VNFS - Vehere Network Forensic System \
  --iso-preparer Vehere Networks \
  --iso-publisher Vehere Networks \
  --iso-volume Vehere-VNFS $LB_CONFIG_OPTIONS

wget -O config/archives/packages-stamus-networks-gpg.key.chroot http://packages.stamus-networks.com/packages.selks4.stamus-networks.com.gpg.key
  
else

  cd VNFS-Live-Build
  #mkdir -p config/packages.chroot/
  #cp ../kernel-misc/*.deb config/packages.chroot/
  lb config \
  -a amd64 -d stretch \
  --archive-areas "main contrib" \
  --swap-file-size 2048 \
  --debian-installer live \
  --bootappend-live "boot=live swap config username=vehere live-config.hostname=VNFS live-config.user-default-groups=audio,cdrom,floppy,video,dip,plugdev,scanner,bluetooth,netdev,sudo" \
  --linux-packages linux-image \
  --linux-packages linux-headers \
  --linux-flavour amd64 \
  --iso-application VNFS - Vehere Network Forensic System \
  --iso-preparer Vehere Networks \
  --iso-publisher Vehere Networks \
  --iso-volume Vehere-VNFS $LB_CONFIG_OPTIONS 

# If needed a "live" kernel can be specified like so.
# In  4 as it uses kernel >4.9 we make sure we keep the "old/unpredictable" naming convention 
# and we take care of that in chroot-inside-Debian-Live.sh
# more info - 
# https://www.freedesktop.org/wiki/Software/systemd/PredictableNetworkInterfaceNames/
#  --linux-packages linux-headers-4.9.20-stamus \
#  --linux-packages linux-image-4.9.20-stamus \
# echo "deb http://packages.stamus-networks.com/selks4/debian-kernel/ stretch main" > config/archives/stamus-kernel.list.chroot

wget -O config/archives/packages-stamus-networks-gpg.key.chroot http://packages.stamus-networks.com/packages.selks4.stamus-networks.com.gpg.key

fi

# Create dirs if not existing for the custom config files
#mkdir -p config/includes.chroot/etc/logstash/conf.d/
mkdir -p config/includes.chroot/etc/skel/Desktop/
mkdir -p config/includes.chroot/usr/share/applications
#mkdir -p config/includes.chroot/etc/logrotate.d/
mkdir -p config/includes.chroot/etc/default/
mkdir -p config/includes.chroot/etc/init.d/
mkdir -p config/includes.binary/isolinux/
#mkdir -p config/includes.chroot/var/log/suricata/StatsByDate/
mkdir -p config/includes.chroot/etc/logrotate.d/
mkdir -p config/includes.chroot/usr/share/images/desktop-base/
#mkdir -p config/includes.chroot/etc/suricata/rules/
mkdir -p config/includes.chroot/etc/profile.d/
mkdir -p config/includes.chroot/root/Desktop/
mkdir -p config/includes.chroot/etc/iceweasel/profile/
mkdir -p config/includes.chroot/etc/conky/
mkdir -p config/includes.chroot/etc/alternatives/
mkdir -p config/includes.chroot/etc/systemd/system/
mkdir -p config/includes.chroot/var/backups/
mkdir -p config/includes.chroot/etc/apt/
mkdir -p config/includes.chroot/opt/
#mkdir -p config/includes.debian-installer/
cd ../

# cp README and LICENSE files to the user's desktop
# cp LICENSE VNFS-Live-Build/config/includes.chroot/etc/skel/Desktop/
# cp LICENSE VNFS-Live-Build/config/includes.chroot/etc/skel/
# some README adjustments - in order to add a http link
# to point to the latest README version located on VNFS github
# The same as above but for root
# cp LICENSE VNFS-Live-Build/config/includes.chroot/root/Desktop/
# some README adjustments - in order to add a http link

# Logstash and Elasticsearch 5 template
#cp staging/etc/logstash/conf.d/* VNFS-Live-Build/config/includes.chroot/etc/logstash/conf.d/ 
#cp staging/etc/logstash/elasticsearch5-template.json VNFS-Live-Build/config/includes.chroot/etc/logstash/ 
#cp -r staging/etc/logstash/templates VNFS-Live-Build/config/includes.chroot/etc/logstash/

# Overwrite Suricata default script
#cp staging/etc/default/suricata VNFS-Live-Build/config/includes.chroot/etc/default/

# Iceweasel bookmarks
cp staging/etc/iceweasel/profile/bookmarks.html VNFS-Live-Build/config/includes.chroot/etc/iceweasel/profile/

# Logrotate config for eve.json
#cp staging/etc/logrotate.d/suricata VNFS-Live-Build/config/includes.chroot/etc/logrotate.d/

cp -r staging/opt/vehere VNFS-Live-Build/config/includes.chroot/opt/
cp staging/etc/addrepo.list.chroot VNFS-Live-Build/config/archives/

# Add the Stmaus Networs logo for the boot screen
cp staging/splash.png VNFS-Live-Build/config/includes.binary/isolinux/
cp staging/menu.cfg VNFS-Live-Build/config/includes.binary/isolinux/
cp staging/install.cfg VNFS-Live-Build/config/includes.binary/isolinux/

# Add the VNFS wallpaper
# cp staging/wallpaper/joy-wallpaper_1920x1080.svg VNFS-Live-Build/config/includes.chroot/etc/alternatives/desktop-background

# Copy banners
cp staging/etc/motd VNFS-Live-Build/config/includes.chroot/etc/
cp staging/etc/issue.net VNFS-Live-Build/config/includes.chroot/etc/

# Copy pythonpath.sh
cp staging/etc/profile.d/pythonpath.sh VNFS-Live-Build/config/includes.chroot/etc/profile.d/
#wait
# Add core system packages to be installed
#linux-image-amd64 linux-headers-amd64
echo "
build-essential bison flex linux-image-amd64 linux-headers-amd64 libnuma-dev autoconf git automake autogen libpcap-dev libtool 
libjson-c-dev libglib2.0 libcurl3-gnutls gnutls-bin libgnutls28-dev libyaml-dev libnetfilter-queue-dev libnet1-dev 
libcap-ng-dev libmagic-dev libjansson-dev libnss3-dev liblua5.1-dev libhiredis-dev libevent-dev libnetfilter-log-dev 
ragel libboost-dev libhyperscan-dev libcurl4-openssl-dev libpython-dev python2.7-dev python-dev python-numpy python-setuptools python-scipy 
gdb strace doxygen libssl1.0 pciutils debhelper quilt libfastjson-dev libestr-dev liblognorm-dev libdnet 
libdnet-dev libdumbnet-dev libmaxminddb-dev python-pip python-yaml network-manager firmware-iwlwifi 
libpcre3 libpcre3-dbg libpcre3-dev ntp libyaml-0-2 zlib1g zlib1g-dev libcap-ng0 make git-core 
pkg-config libnetfilter-queue1 libnfnetlink-dev libnfnetlink0 libluajit-5.1-dev libjansson4 libnspr4-dev 
libgeoip1 libgeoip-dev rsync mc python-daemon libnss3-tools curl net-tools python-daemon 
python-crypto libgmp10 python-simplejson python-pygments ssh sudo tcpdump nginx openssl 
jq patch debian-installer-launcher live-build apt-transport-https gpsd gpsd-clients ntp ntpstat xrdp

 " \
>> VNFS-Live-Build/config/package-lists/VNFSNetworks-CoreSystem.list.chroot

# Add system tools packages to be installed
echo "
ethtool bwm-ng iptraf htop rsync tcpreplay sysstat hping3 screen ngrep 
tcpflow dsniff mc python-daemon wget curl vim bootlogd lsof" \
>> VNFS-Live-Build/config/package-lists/VNFSNetworks-Tools.list.chroot

# Unless otherwise specified the ISO will be with a Desktop Environment
if [[ -z "$GUI" ]]; then 
  echo "lxde fonts-lyx wireshark terminator conky" \
  >> VNFS-Live-Build/config/package-lists/VNFSNetworks-Gui.list.chroot
  # Copy conky conf file
  cp staging/etc/conky/conky.conf VNFS-Live-Build/config/includes.chroot/etc/conky/
  
  # For setting up Suricata IDS interface.
  # cp staging/usr/share/applications/Setup-IDS-Interface.desktop VNFS-Live-Build/config/includes.chroot/usr/share/applications/
fi

# If -p (add packages) option is used - add those packages to the build
if [[ -n "${PKG_ADD}" ]]; then 
  echo " ${PKG_ADD[@]} " >> \
  VNFS-Live-Build/config/package-lists/VNFSNetworks-UsrPkgAdd.list.chroot
fi

# Add specific tasks(script file) to be executed 
# inside the chroot environment
cp staging/config/hooks/chroot-inside-Debian-Live.hook.chroot VNFS-Live-Build/config/hooks/normal/

# Edit menu names for Live and Install
if [[ -n "$KERNEL_VER" ]]; 
then
  
   # IF custom kernel option is chosen "-k ...":
   # remove the live menu since different kernel versions and custom flavors  
   # can potentially fail to load in LIVE depending on the given environment.
   # So we create a file for execution at the binary stage to remove the 
   # live menu choice. That leaves the options to install.
   cp staging/config/hooks/menues-changes-live-custom-kernel-choice.binary VNFS-Live-Build/config/hooks/
   cp staging/config/hooks/menues-changes.binary VNFS-Live-Build/config/hooks/
   
else
  
  cp staging/config/hooks/menues-changes.hook.binary VNFS-Live-Build/config/hooks/
  
fi

# Debian installer preseed.cfg
echo "
d-i netcfg/disable_autoconfig boolean true
d-i netcfg/dhcp_failed note
d-i netcfg/dhcp_options select Configure network manually 
d-i netcfg/hostname string VEHERE
d-i passwd/user-fullname string vehere User
d-i passwd/username string vehere
d-i passwd/user-password password admin
d-i passwd/user-password-again password admin
d-i passwd/user-default-groups string audio cdrom floppy video dip plugdev scanner bluetooth netdev sudo
d-i passwd/root-password password admin
d-i passwd/root-password-again password admin
" > VNFS-Live-Build/config/includes.installer/preseed.cfg

# Build the ISO
version=2
patch_number=2
release_month=5
release_year=19

cd VNFS-Live-Build && ( lb build 2>&1 | tee build.log )
mv live-image-amd64.hybrid.iso vipl_NTPServer.iso
