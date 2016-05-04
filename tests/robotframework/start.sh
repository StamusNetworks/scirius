#!/bin/bash
set -e
BROWSER=iceweasel
#BROWSER=chromium

if [ "$(pidof Xvnc4)" == "" ]
then
	vnc4server :1
fi

# Chrome requires to find chromedriver available in PATH
if [ "$BROWSER" == "chromium" ]
then
	RF_BROWSER=chrome
else
	RF_BROWSER=firefox
fi

export DISPLAY=:1
if [ "$(pidof $BROWSER)" == "" ] || [ "$BROWSER" == "chromium" ]
then
	if [ "$BROWSER" == "chromium" ]
	then
		killall -9 chromium ||:
		sleep 5
		export PATH=$PATH:/usr/lib/chromium
		$BROWSER --no-webgl --no-sandbox &
	else
		iceweasel &
	fi
	sleep 10
fi

pybot -v BROWSER:$RF_BROWSER "$@"
