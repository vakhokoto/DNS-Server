#!/bin/bash
# Usage: ./test.sh
#        ./test.sh {path_to_dns_server}
SERVER="./dns_server.py"
if [ "$#" -eq 1 ]; then
    SERVER=$1
fi
CONFIG="config/"
IP="127.0.0.1"
PORT=5356
TIMEOUT=1
LOG=0
ERROR_FILE='error.log'

PARAMS=(A MX NS TXT SOA AAAA CNAME)

DEBUG_LOG(){
    CUR_SCORE=$1
    DOMAIN=$2
    FLAG=$3
    if [ $CUR_SCORE -eq "1" ]; then
        BOOL='True'
    else
        BOOL='False'
    fi
    filler='         '
    line='----------------------------------------'
    spac='                    '
    R1=$(printf "* %s %s |" $DOMAIN  "${spac:${#DOMAIN}}" )
    RES="$R1 $FLAG"
    printf "%s %s %s %s\n" "$R1" $FLAG "${line:${#RES}}" $BOOL
}

run_test(){
    TEST_COUNT=${#ANS[*]}
    for (( i=0; i<=$(( $TEST_COUNT -1 )); i++ )); do
        FLAG=${PARAMS[$i]}
        CUR_SCORE=$(timeout ${TIMEOUT}s dig -t ${FLAG} +noall +answer $DOMAIN @$IP -p $PORT | grep -q "${ANS[${FLAG}]}" ; echo $((1-$?)))
        SCORE=$((SCORE + $CUR_SCORE))
        
        DEBUG_LOG ${CUR_SCORE} ${DOMAIN} ${FLAG}
        FULL_SCORE=$((FULL_SCORE + 1))
    done
    echo
}

test_configuration(){
    echo "### Testing Zone Files..."
    # example.com
    DOMAIN=example.com
    declare -A ANS=([A]="1.1.1.1" [MX]="aspmx.l.example.com" [NS]="ns1.example.com" [TXT]="v=spf1 mx ~all" [SOA]="2019100600" [AAAA]="2406:da00:ff00::22ce:806" [CNAME]="example.com")
    run_test
    
    # example2.com
    DOMAIN=example2.com
    declare -A ANS=([A]="38.21.5.14" [MX]="aspmx.l.example2.com" [NS]="ns1.example2.com" [TXT]="v=spf1 a mx ip4:69.64.153.131" [SOA]="2019100600" [AAAA]="2406:da00:ff00::22ce:806" [CNAME]="example2.com")
    run_test
    
    # FreeUniCN19.com
    DOMAIN=FreeUniCN19.com
    declare -A ANS=([A]="4.8.15.16" [MX]="aspmx.l.FreeUniCN19.com" [NS]="ns1.FreeUniCN19.com" [TXT]="You Shall Not Pass!" [SOA]="2020506078" [AAAA]="dae7:b6c9:6c51:c4d8:1ae3:abf9:1960:c1b2" [CNAME]="FreeUniCN19.com")
    run_test
}

test_outside(){
    echo "### Testing Outside of configurations..."
    # # twitch.tv
    DOMAIN=twitch.tv
    declare -A ANS=([A]="151.101.66.167" [MX]="aspmx.l.google.com." [NS]="ns1.p18.dynect.net." [TXT]="v=spf1 include:_spf.google.com include:amazonses.com" [SOA]="admin.justin.tv.")
    run_test
    
    # stackoverflow.com
    DOMAIN=stackoverflow.com
    declare -A ANS=([A]="151.101.193.69" [MX]="aspmx.l.google.com." [NS]="ns-358.awsdns-44.com." [TXT]="MS=ms52592611")
    run_test
    
    # freeuni.edu.ge
    DOMAIN=freeuni.edu.ge
    declare -A ANS=([A]="185.163.200.15" [MX]="ASPMX.L.GOOGLE.COM." [NS]="ns1.proservice.ge." [TXT]="v=spf1 +a +mx +ip4:74.125.43.121" [SOA]="2019012400" )
    run_test
}

test_cache(){
    echo "### Testing Caching..."
    # github.com
    DOMAIN=github.com
    cache_time1=($(timeout ${TIMEOUT}s dig -t A $DOMAIN @$IP -p $PORT | awk '/Query time/ {print $4}'))
    [ -z $cache_time1 ] && cache_time1=0
    echo "* $DOMAIN 1st try: time ${cache_time1}"
    
    cache_time2=($(timeout ${TIMEOUT}s dig -t A $DOMAIN @$IP -p $PORT | awk '/Query time/ {print $4}'))
    [ -z $cache_time2 ] && cache_time2=0
    
    echo "* $DOMAIN 2nd try: time ${cache_time2}"
    
    [ $(($cache_time1 / 2)) -ge $cache_time2 ] && [ $cache_time1 -ne 0 ] && SCORE=$((SCORE + 2))
    FULL_SCORE=$((FULL_SCORE + 2))
    echo
    
    # pastebin.com
    DOMAIN=pastebin.com
    cache_time1=($(timeout ${TIMEOUT}s dig -t MX $DOMAIN @$IP -p $PORT | awk '/Query time/ {print $4}'))
    [ -z $cache_time1 ] && cache_time1=0
    echo "* $DOMAIN 1st try: time ${cache_time1}"
    
    cache_time2=($(timeout ${TIMEOUT}s dig -t MX $DOMAIN @$IP -p $PORT | awk '/Query time/ {print $4}'))
    [ -z $cache_time2 ] && cache_time2=0
    echo "* $DOMAIN 2nd try: time ${cache_time2}"
    
    [ $(($cache_time1 / 2)) -ge $cache_time2 ] && [ $cache_time1 -ne 0 ] && SCORE=$((SCORE + 2))
    FULL_SCORE=$((FULL_SCORE + 2))
    echo
}

declare -i SCORE=0
declare -i FULL_SCORE=0
if [ -f $SERVER ]; then
    # redirect logs
    if [ $LOG -eq "0" ]; then
        DBG='> /dev/null'
    fi
    
    # launch program
    eval python3 $SERVER $CONFIG $IP $PORT $DBG  &
    SPID=$!
    sleep 1
    
    # run tests
    test_configuration
    test_outside
    test_cache
    
    # Show Result
    echo "Score : ${SCORE}/${FULL_SCORE}"
    echo "Total score: " $(((SCORE*100 / FULL_SCORE )))%
    echo $1
    
    # Kill Process/dns port
    # read -p "press enter to kill process"
    sudo kill -9 $SPID
    fuser -k $PORT/udp
else
    echo "File $FILE does not exist"
fi