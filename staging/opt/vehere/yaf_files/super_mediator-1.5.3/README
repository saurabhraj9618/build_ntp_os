super_mediator
===============

super_mediator is an IPFIX mediator for use with YAF and SiLK tools.  It 
processes YAF output data (IPFIX files or via TCP, UDP, or Spread from a
YAF process) and exports that data in IPFIX or CSV Text format to one or more
collectors (e.g. flowcap, rwflowpack) or files (e.g. bulk upload to database).

super_mediator can provide simple filtering on collection or at export time.
super_mediator has the ability to filter by IP address in an IPset but requires
the SiLK IPset library.  Install the library before configuring super_mediator
with the --with-skipset to ./configure.

super_mediator can be configured to pull the Deep Packet Inspection data from
YAF that SiLK can not collect and export that information to another IPFIX
collector, or simply export the data to a CSV/JSON file for bulk upload into a 
database of your choice.  Given MySQL credentials, super_mediator will
import the files into the given database.

super_mediator can also be configured to perform de-duplication on DPI 
protocol information exported by YAF. 
It will export the de-duplicated records in IPFIX, CSV, or JSON format.  
See the man pages for more information.

super_mediator is configured using the super_mediator.conf file.  You must
use the configuration file if more than one collector or exporter is needed. 
Otherwise, simple command line arguments are provided for one collector 
to one exporter.

Building
==========

super_mediator requires glib 2.12.0 or later; glib is available at 
http://www.gtk.org.  Build and install glib before building super_mediator.
Note that glib is also included in many operating environments or ports 
collections.

super_mediator requires libfixbuf 1.7.0 or later; libfixbuf is available at
http://tools.netsa.cert.org/fixbuf.  Build and install libfixbuf before
building the super_mediator.

Spread support requires Spread 4.1 or later.  Build and install Spread before
building super_mediator if Spread is your desired transport protocol.  Run
./configure --with-spread to enable Spread in the super_mediator.

super_mediator uses a standard autotools-based build system.  The customary
build procedure (./configure && make && make install) should work in 
most environments.  

If mysql libraries are available, the super_table_creator program will also be
built.  Given a few mysql parameters (name, password, database) the 
super_table_creator will create a database and the necessary tables for using
the default super_mediator DPI CSV output.  To disable building the 
super_table_creator, configure with --with-mysql=no.

If you prefer cmake as your build system (cmake . && make) should suffice.
It may be necessary to set CMAKE_LIBRARY_PATH and CMAKE_INCLUDE_PATH 
environment variables to the locations of the MySQL libraries and headers if
compiled with MySQL support.

In either build system, pkg-config(1) is used to find libfixbuf.
You may need to set the PKG_CONFIG_PATH to the location of
libfixbuf.pc.

Known Issues
=============

Please send bug reports, feature requests, and questions to 
<netsa-help@cert.org>.  
