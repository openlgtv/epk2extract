To compile on Ubuntu 12.04LTS:
==============================

apt-get install cmake liblzo2-dev

./cmake

make

## To use:
put *.pem and AES.key to epk2extract folder
run it via sudo because rootfs extraction needs root
sudo ./epk2extract file

## How to get IDC from SYM run:
./epk2extract xxxxxxxx.SYM

## Known issues:
Sometimes it segfaults on some partitions. In that case just rerun it again.

