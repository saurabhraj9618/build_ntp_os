#!/bin/bash

set -e

# Setting up the LIVE root (during install on disk it is preseeded)
echo "root:admin" | chpasswd

# Enable color output and the "ll" command in shell 
echo " export LS_OPTIONS='--color=auto'" >> /root/.bashrc
echo " alias ll='ls $LS_OPTIONS -l'" >> /root/.bashrc

###  Set up repos ###

wget -qO - http://packages.stamus-networks.com/packages.stamus-networks.com.gpg.key | apt-key add - 
wget -qO - http://packages.stamus-networks.com/packages.selks4.stamus-networks.com.gpg.key | apt-key add - 
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
wget -qO - https://evebox.org/files/GPG-KEY-evebox | sudo apt-key add -

cat >> /etc/apt/sources.list.d/elastic-5.x.list <<EOF
deb https://artifacts.elastic.co/packages/5.x/apt stable main
EOF

cat >> /etc/apt/sources.list.d/curator5.list <<EOF
deb http://packages.elastic.co/curator/4/debian stable main
EOF

cat >> /etc/apt/sources.list.d/evebox.list <<EOF
deb http://files.evebox.org/evebox/debian stable main
EOF

cat >> /etc/apt/sources.list.d/selks4.list <<EOF
# SELKS4 Stamus Networks repos
#
# Manual changes here can be overwritten during 
# SELKS updates and upgrades !!

deb http://packages.stamus-networks.com/selks4/debian/ stretch main
deb http://packages.stamus-networks.com/selks4/debian-kernel/ stretch main
#deb http://packages.stamus-networks.com/selks4/debian-test/ stretch main
EOF

###  END Set up repos ###

mkdir /opt/vehere

cd /opt/vehere

### START Suricata ###

apt-get update && \
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" suricata 

### END Suricata ###

### START JAVA for ELK ###

apt-get update && \
apt-get install -y ca-certificates-java openjdk-8-jre-headless \
openjdk-8-jdk openjdk-8-jre openjdk-8-jre-headless

### END JAVA for ELK ###

### START ELK ###

apt-get update && \
apt-get install -y elasticsearch logstash kibana elasticsearch-curator

mkdir -p /var/cache/logstash/sincedbs/
chown logstash:logstash /var/cache/logstash/sincedbs/

sudo /bin/systemctl enable elasticsearch && \
sudo /bin/systemctl enable logstash && \
sudo /bin/systemctl enable kibana && \
sudo /bin/systemctl daemon-reload

### END ELK ###

### START Install kibana dashboards ###

apt-get install -y kibana-dashboards-stamus

# reset the dashboards after the package upgrade
rm -rf /etc/kibana/kibana-dashboards-loaded

### END Install kibana dashboards ###

################# PF-Ring & libpcap #######################
cd /opt/vehere
wget http://apt-stable.ntop.org/stretch/all/apt-ntop-stable.deb
sudo dpkg -i apt-ntop-stable.deb
sudo apt-get update
sudo apt-get install pfring
sudo apt-get install -f


############Please ensure that you set your LD_LIBRARY_PATH to include /usr/local/lib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

echo "/usr/local/lib" >> /etc/ld.so.conf.d/libc.conf


###########Get DKMS#################
git clone https://github.com/dell/dkms.git
cd dkms
make
chmod +x dkms

############Get PF_RING from github#############
git clone https://github.com/ntop/PF_RING.git
cd PF_RING/userland
./configure
make

cd PF_RING/userland
make install

cd PF_RING/userland/libpcap
make
sudo make install

## Then remove the original /libpcap from /usr/lib/x86_64-linux-gnu directory
cd /usr/lib/x86_64-linux-gnu
mv libpcap.so.1.8.1 libpcap.so.1.8.1.orig
mv libpcap.a libpcap.a.orig
cp /usr/local/lib/libpcap.so.1.8.1 .
cp /usr/local/lib/libpcap.a .
rm libpcap.so
rm libpcap.so.0.8
ln -s libpcap.so.1.8.1 libpcap.so.0.8
ln -s libpcap.so.0.8 libpcap.so
cp /opt/vehere/PF_RING/tools/n2if /usr/local/bin

################# nDPI ########################
git clone https://github.com/ntop/nDPI.git
cd nDPI
./autogen.sh
./configure
make
make install


cd src/lib 
cp -r third_party /usr/local/lib/


############################Install Spread###################

cd /opt/vehere/
wget http://download.openpkg.org/components/cache/spread/spread-src-5.0.0.tar.gz
tar xaf spread-src-5.0.0.tar.gz

cd spread-src-5.0.0/daemon

## There will be a need to correct an error in file protocol.c in the directory spread-src-5.0.0/daemon.
##vi protocol.c ## go to line 96 and change the line to
##	Static sp_time		Zero_timeout	= { 0, 0 };
cd ..
./configure
make
make install


#################Install libfixbuf#################
cd /opt/vehere/
wget https://tools.netsa.cert.org/fixbuf/download.html#
tar xaf libfixbuf-1.8.0.tar.gz

cd libfixbuf-1.8.0/

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
./configure --enable-debug --with-spread=/usr/local
make install


###################Install libschemaTools-1.2.1##############
cd /opt/vehere/libschemaTools-1.2.1
./configure
make
make install

###################Install p0flib################
cd /opt/vehere/p0flib/libp0f
./configure
make
make install

#################Install silk-3.16.0###################
cd /opt/vehere/silk-3.16.0
./configure --enable-debugging --enable-gprof --enable-ipv6 --enable-localtime –with-python
make
make install

sudo cp ./site/generic/silk.conf /usr/local/etc

#################################Install yaf-2.9.3#######################

cd /opt/vehere/yaf-2.9.3
##You may need to change all occurrences of nDPI version from 1.8.0 in the configure script to something that is greater than 2.8.0. 
./configure --enable-ndpi --enable-plugins --enable-applabel --enable-entropy --enable-fpexporter --enable-p0fprinter --enable-mpls --enable-nonip --enable-localtime --with-libpcap=/usr/local --with-pfring=/usr/local --with-spread=/usr/local
make
##You may need to change a few things in the src/yaftab.c file-
##a. On line 2507, change flow->ndpi_sub = proto.protocol; to flow->ndpi_sub = proto.app_protocol
##b. On line 1323, change ndpi_init_detection_module… to ndpi_init_detection_module();
##c. On line 1385, change ndpi_exit_detection_module(flowtab->ndpi_struct, yf_free); to ndpi_exit_detection_module(flowtab->ndpi_struct); 
make install

############################Install super_mediator-1.5.3###############################
cd /opt/vehere/super_mediator-1.5.3
./configure --with-spread=/usr/local

##You may need to change a line in the file ~/Downloads/source/super_mediator-1.5.3/src/mediator_json.c
##539,541c539,541
##<     if(lfp!=NULL){
##<        rc = fwrite(str->str, 1, str->len, lfp);
##<     }
make
make install

####################################Install snarf####################
apt-get install -y protobuf-c-compiler libprotobuf-c-dev
apt-get install -y libzmq3-dev
cd /opt/vehere/snarf-0.3.0
./configure
make
make install

#################################Install Analysis Pipeline#####################
cd /opt/vehere/analysis-pipeline-5.7
./configure
make
make install


############################Install logstash plugin translate & logstash plugin math###################
sudo /usr/share/logstash/bin/logstash-plugin install logstash-filter-translate
sudo /usr/share/logstash/bin/logstash-plugin install logstash-filter-math


##################Download public_suffix_list file from https://github.com/publicsuffix/list
git clone https://github.com/publicsuffix/list
cp public_suffix_list.dat /usr/local/etc 


##########Create a directory /usr/local/etc/dictionaries

mkdir /usr/local/etc/dictionaries

cp /opt/vehere/dictionaries/*.* /usr/local/etc/dictionaries/

###########################Copy the logstash scripts and template

cp -r /opt/vehere/templates  /etc/logstash/

cp /opt/vehere/conf.d/*.* /etc/logstash/conf.d/

cp -r /opt/vehere/geoip  /usr/local/etc/

######################Create /var/log/vehere/dpi /var/log/vehere/stat ##########
mkdir /var/log/vehere
mkdir /var/log/vehere/dpi
mkdir /var/log/vehere/stats
mkdir /var/log/vehere/ruleengine

chown logstash:logstash /var/log/vehere

########################Copy Startall and startpipeline script#################


cp /opt/vehere/startall.sh /usr/local/bin/

chmod +x /usr/local/bin/startall.sh

cp /opt/vehere/startpipeline.sh /usr/local/bin/

chmod +x /usr/local/bin/startpipeline.sh


################### START Scirius, nginx, revrse proxy, supervisor and ssl ###

# NOTE python-pip is already installed in the build script

#pip install --upgrade 'django<1.9' django-tables2 GitPython pyinotify flup
#pip install --upgrade six
#pip install django-dbbackup django-bootstrap3 django-revproxy ipy 

mkdir -p /var/lib/scirius/static/
apt-get update && \
apt-get install -y scirius

# supervisor conf
ln -s /usr/share/doc/scirius/examples/scirius-supervisor.conf /etc/supervisor/conf.d/scirius-supervisor.conf

# Set the right permissions for the logstash user to run suricata
chown -R logstash:logstash /var/log/suricata

# www-data needs to write Suricata rules
chown -R www-data.www-data /etc/suricata/rules/

mkdir -p /etc/nginx/ssl
openssl req -new -nodes -x509 -subj "/C=FR/ST=IDF/L=Paris/O=Stamus/CN=SELKS" -days 3650 -keyout /etc/nginx/ssl/scirius.key -out /etc/nginx/ssl/scirius.crt -extensions v3_ca 

rm /etc/nginx/sites-enabled/default

cat >> /etc/nginx/sites-available/selks4.conf <<EOF
server {
    listen 127.0.0.1:80;
    listen 127.0.1.1:80;
    listen 443 default_server ssl;
    ssl_certificate /etc/nginx/ssl/scirius.crt;
    ssl_certificate_key /etc/nginx/ssl/scirius.key;
    server_name SELKS;
    access_log /var/log/nginx/scirius.access.log;
    error_log /var/log/nginx/scirius.error.log;

    # https://docs.djangoproject.com/en/dev/howto/static-files/#serving-static-files-in-production
    location /static/ { # STATIC_URL
        alias /var/lib/scirius/static/; # STATIC_ROOT
        expires 30d;
    }

    location /media/ { # MEDIA_URL
        alias /var/lib/scirius/static/; # MEDIA_ROOT
        expires 30d;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_read_timeout 600;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_redirect off;
    }

}
EOF

# enable sites
ln -s /etc/nginx/sites-available/selks4.conf /etc/nginx/sites-enabled/selks4.conf

cd /usr/share/python/scirius/ && \
source bin/activate
python bin/manage.py loaddata /etc/scirius/scirius.json
python bin/manage.py addsource "ETOpen Ruleset" https://rules.emergingthreats.net/open/suricata-git/emerging.rules.tar.gz http sigs
python bin/manage.py addsource "SSLBL abuse.ch" https://sslbl.abuse.ch/blacklist/sslblacklist.rules http sig
python bin/manage.py defaultruleset "Default SELKS ruleset"
##python bin/manage.py disablecategory "Default SELKS ruleset" stream-events
python bin/manage.py addsuricata SELKS "Suricata on SELKS" /etc/suricata/rules "Default SELKS ruleset"
python bin/manage.py updatesuricata
deactivate

/usr/bin/supervisorctl reread && \
/usr/bin/supervisorctl update && \
/usr/bin/supervisorctl restart scirius && \
/bin/systemctl restart nginx
sudo /bin/systemctl enable supervisor

# set permissions for Scirius 
touch /var/log/scirius.log
touch /var/log/scirius-error.log
chown www-data /var/log/scirius*
chown -R www-data /var/lib/scirius/git-sources/
chown -R www-data /var/lib/scirius/db/
chown -R www-data.www-data /etc/suricata/rules/

# fix permissions for user www-data/scirius
usermod -a -G logstash www-data
mkdir -p /var/run/suricata/
chmod g+w /var/run/suricata/ -R

### END Scirius, nginx, revrse proxy, supervisor and ssl ###

# Set up a curator old logs removal
# flush everything that is older than 2 weeks

cat >> /opt/selks/delete-old-logs.sh <<EOF
#!/bin/bash

/opt/elasticsearch-curator/curator_cli delete_indices --filter_list \
'
[
  {
    "filtertype": "age",
    "source": "creation_date",
    "direction": "older",
    "unit": "days",
    "unit_count": 14
  },
  {
    "filtertype": "pattern",
    "kind": "prefix",
    "value": "logstash*"
  }
]
'
EOF

chmod 755 /opt/selks/delete-old-logs.sh

# Set up a cron jobs for Logstash, Scirius, rule updates
echo "0 2 * * * www-data ( cd /usr/share/python/scirius/ && . bin/activate && python bin/manage.py updatesuricata && deactivate )" >> /etc/crontab
echo "0 4 * * * root /opt/selks/delete-old-logs.sh" >> /etc/crontab
# alway leave a empty line before cron files end
echo "" >> /etc/crontab

# Set up the host name
echo "VEHERE" > /etc/hostname

# Enable the ssh banners
sed -i -e 's|\#Banner \/etc\/issue\.net|Banner \/etc\/issue\.net|'  /etc/ssh/sshd_config


# Edit the Icon "Install Debian Stretch" name on a Live Desktop
# to "Install SELKS"
sed -i -e 's|Name\=Install Debian sid|Name\=Install Intelliworker|'  /usr/share/applications/debian-installer-launcher.desktop 

# Install exception for local certificate
certutil -A -n VEHERE -t "P,p,p"  -i /etc/nginx/ssl/scirius.crt  -d /etc/iceweasel/profile/
chmod a+r /etc/iceweasel/profile/*db

apt-get update && \
apt-get install -y linux-headers-amd64

# Clean devel and some others packages
apt-get -y remove bison  autoconf automake libc6-dev autotools-dev libpcap-dev libnet1-dev libcap-ng-dev \
	libnetfilter-queue-dev  libnss3-dev libnspr4-dev libyaml-dev \
	xscreensaver xscreensaver-data manpages-dev libjansson-dev \
	ghostscript xmms2-core x11proto-core-dev linux-libc-dev \
	rpm alien sane-utils libsane rpm2cpio \
	libx11-dev libx11-doc m4

apt-get autoremove -y
apt-get clean && \
cat /dev/null > ~/.bash_history && history -c
