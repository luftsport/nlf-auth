#!/bin/bash

WORKING_DIR="${PWD}/"
PID_FILE="/var/local/run/nlf_auth/nlf_auth.pid"
cd $WORKING_DIR

if [ ! -f $PID_FILE ];then
        echo "No pid file, exiting"
else
        kill -15 `cat ${PID_FILE}`
        echo "Killed process from pid file"
        #Should wait and recheck and if still pid, then kill -9
fi

