#!/bin/bash

firmware=$1
bwext=$2
base_name=$(basename $1)
log_dir=$bwext/$base_name.log
ff1=cer
ff2=rsa

rm -rf $log_dir
mkdir $log_dir


rm -rf $bwext/_$base_name.extracted
binwalk -e $1 --rm -C $bwext

rootfs="squashfs-root" #algorithm to find rootfs. hardcoded atm
rfs_loc=$bwext/_$base_name.extracted/

find $rfs_loc -maxdepth 3 -type f -exec binwalk {} --dd=.$ff1 --dd=.$ff2 --directory $rfs_loc  -y $ff1 -y $ff2 -v -f $log_dir/binwalk_ext_out.csv --csv \;

pcregrep -M '(FILE.+\n(.*\n).+\n+^((?!FILE)))' $log_dir/binwalk_ext_out.csv > $log_dir/found.txt

echo results file : $log_dir/found.txt

#echo extracted folder and where the found extractions are (if any)
#echo root-fs location into a file