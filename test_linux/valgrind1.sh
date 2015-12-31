#!/bin/sh

# Execution of pem2der with its own walker (function use_my_own_pem_walker())

PRG=../pem2der

#find -name "*.pem" -exec ls -al {} \;

#exit 1

find -name "*.pem" -exec valgrind --leak-check=full --show-leak-kinds=all ${PRG} --password pwd1 {} \;
