#!/bin/sh

if [ "$1" = "dma" ]; then
	BITFILE=17012017-cheri128-de4-theo-msgdma.sof.bz2
else
	BITFILE=20160601-cheri128-de4-jdw57.sof.bz2
fi


./berictl -j loadsof -z $BITFILE && \
./berictl -j loadbin -z /home/rb743/kernel.bz2 0x100000 && \
./berictl -j boot && ./berictl -j console
