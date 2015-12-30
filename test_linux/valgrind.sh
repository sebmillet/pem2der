#!/bin/sh

PRG=../pem2der

#find -name "*.pem" -exec ls -al {} \;

#exit 1

find -name "*.pem" -exec valgrind --leak-check=full --show-leak-kinds=all ${PRG} --password pwd1 {} \;
