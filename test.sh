#!/bin/bash -x

SERVER="./dns_server.py"
CONFIG="config/"
IP="127.0.0.1"
PORT=1053

declare -i SCORE=0
if [ -f $SERVER ]; then
	python3 $SERVER $CONFIG $IP $PORT &
	SPID=$!
	sleep 1

	## run tests
	# 6 points: A', 'NS', 'MX', 'TXT', 'SOA', 'CNAME', 'AAAA'
	SCORE=$((SCORE + $(dig -t A +noall +answer example.com @$IP -p $PORT | grep -c 1.1.1.1)))
	SCORE=$((SCORE + $(dig -t MX +noall +answer example.com @$IP -p $PORT | grep -c aspmx.l.example.com)))
	SCORE=$((SCORE + $(dig -t NS +noall +answer example.com @$IP -p $PORT | grep -c 'ns1.example.com')))
	SCORE=$((SCORE + $(dig -t TXT +noall +answer example.com @$IP -p $PORT | grep -c "v=spf1 mx ~all")))
	SCORE=$((SCORE + $(dig -t SOA +noall +answer example.com @$IP -p $PORT | grep -c "2019100600")))
	SCORE=$((SCORE + $(dig -t AAAA +noall +answer example.com @$IP -p $PORT | grep -c "ff00")))

	# 5 points: 
	SCORE=$((SCORE + 5 * $(dig -t A +noall +answer twitch.tv @$IP -p $PORT | grep -c 151.101.66.167)))

	# 5 points check caching
	cache_time1=($(dig -t A on.ge @$IP -p $PORT | awk '/Query time/ {print $4}'))
	cache_time2=($(dig -t A on.ge @$IP -p $PORT | awk '/Query time/ {print $4}'))
	[ $(($cache_time1 / 2)) -ge $cache_time2 ] && [ $cache_time1 -ne 0 ] && SCORE=$((SCORE + 5))

	echo "Total score: " $((($SCORE / 11 )* 100))
	
	#sudo kill -- -$PID
	echo $1
	read -p "press enter to kill process" 
	sudo kill -9 $SPID
else
   echo "File $FILE does not exist"
fi