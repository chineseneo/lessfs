#umount /mnt
#echo >/etc/exports
#exportfs -r
umount /fuse
rm /core.*
rm -rf /data/mta
rm -rf /data/dta
if [ -f /etc/init.d/syslog ]
  then
    /etc/init.d/syslog stop
  else
    /etc/rc.d/rc.syslog stop
fi
rm -f /var/log/localmessages
touch /var/log/localmessages
if [ -f /etc/init.d/syslog ]
   then
     /etc/init.d/syslog start
   else
     /etc/rc.d/rc.syslog start
fi
./mklessfs -f -c /etc/lessfs.cfg
#./lessfs /etc/lessfs.cfg /fuse  -o negative_timeout=0,entry_timeout=0,attr_timeout=0,use_ino,readdir_ino,default_permissions,allow_other
#./lessfs /etc/lessfs.cfg /fuse  -o negative_timeout=0,entry_timeout=0,attr_timeout=0,use_ino,readdir_ino,default_permissions,allow_other,big_writes,max_read=65536,max_write=65536
./lessfs /etc/lessfs.cfg /fuse -o hard_remove,negative_timeout=0,entry_timeout=0,attr_timeout=0,use_ino,readdir_ino,default_permissions,allow_other,big_writes,max_read=131072,max_write=131072
#echo "/fuse  127.0.0.1(no_root_squash,rw,fsid=root,no_subtree_check)" >/etc/exports
#exportfs -r
#mount localhost:/fuse /mnt -o rsize=65536,wsize=65536,nfsvers=3,hard
