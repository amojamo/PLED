#!/bin/bash
now=`date +"%Y_%m_%d"`
filename=backupdf_vol_$now.tar
sudo /bin/tar -cf "/home/ubuntu/dfbackup/$filename" /bitnami/
