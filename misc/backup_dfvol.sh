#!/bin/bash
now=`date +"%Y_%m_%d"`
filename=backupdf_vol_$now.tar
sudo /bin/tar -zcf "/home/backupbot/backup/dfbackup/$filename" /bitnami/
