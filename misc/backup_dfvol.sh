#!/bin/bash
now=`date +"%Y_%m_%d"`
filename=backupdf_vol_$now.tar
sudo /bin/tar -zcf "/backup/dfbackup/$filename" /bitnami/
