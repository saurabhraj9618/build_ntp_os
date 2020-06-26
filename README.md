# scripts for building NTP iso

## run from terminal
``sudo ./install-deps.sh``

``sudo ./build-debian-live.sh``

### iso file will be created in folder named VNFS-Live-Build

### packages installed in iso: gpsd, gpsd-clients, ntp, ntpstat, xrdp

### to check GPS coordinates coming
``cgps -s``

### to query NTP parameters
``ntpq -p``

### to check synchronization of NTP server
``ntpstat -pq``

### to run gpsd2udp application
#### click the "gps2udp" application under accessories 
