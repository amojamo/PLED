#!/bin/bash
WD=${PWD}
CHECKFILE='checked.txt'
REQFILE='requirements.txt'
echo "Creating save file..."
{
    touch $WD/$CHECKFILE
} &>/dev/null

echo "Installing requirements..."
installReq() { 
	dpkg -s python3-pip &>/dev/null
	if [ $? -eq 0 ]; then
    	echo "python3-pip installed, installing from $REQFILE"
    	pip3 install -r $WD/$REQFILE
    else
    	echo 'python3-pip not installed, installing...'
    	apt install python3-pip -y && installReq
    	
    fi

}

installReq