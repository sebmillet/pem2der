#!/bin/sh

# Execution of pem2der with ppem's walker (function use_pem_walker_provided_by_ppem())

PRG=../pem2der

#find -name "*.pem" -exec ls -al {} \;

#exit 1

find -name "*.pem" -exec valgrind --leak-check=full --show-leak-kinds=all ${PRG} -w --password pwd1 {} \;
