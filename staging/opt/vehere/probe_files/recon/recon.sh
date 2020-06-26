#!/bin/bash
cd /usr/local/bin/recon
taskset -c 0,1 java -Xms2g -Xmx2g  -jar Reconstructor.jar
