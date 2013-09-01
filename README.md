To compile on Ubuntu 12.04LTS:
==============================

apt-get install cmake liblzo2-dev

./cmake

make

To get IDC from SYM run: ./epk2extract xxxxxxxx.SYM

Known issues: sometimes it Segfaults or skips extracting some partitions. In that case rerun it until it's ok.
