#!/bin/bash

for((i=0x2800;i<0x3000;i+=0x8));
do
#echo $i
./test.py REMOTE INFO 120.78.192.35 9999 $i
#./test.py INFO a a 0xb70
done
