#!/bin/bash -x

dd if=/dev/zero of=XTEST count=10000 bs=1024
echo "Start"
date
sleep 10
for PART in 1 2 3 4 5 6; do
    echo "Transfer part ${PART}"
    date
    scp XTEST jsommers@clab.colgate.edu:~
    scp jsommers@clab.colgate.edu:~/XTEST .
    echo "Waiting 10 sec"
    sleep 10
done
date
echo "Done"
