#!/bin/bash
set -e

if [ "$(pidof Xvnc4)" == "" ]
then
	vnc4server :1
fi

export DISPLAY=:1

if [ "$(pidof iceweasel)" == "" ]
then
	iceweasel &
	sleep 10
fi

pybot "$@" .
