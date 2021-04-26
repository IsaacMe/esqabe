# This is a Python framework to compliment "Peek-a-Boo, I Still See You: Why Efficient Traffic Analysis Countermeasures Fail".
# Copyright (C) 2012  Kevin P. Dyer (kpdyer.com)
# See LICENSE for more details.

import os

# Set the following to a directory that contains
# * weka-X-Y-Z (see WEKA_ROOT to change the weka version)
# * pcap-logs (a diretory that contains all of the LL pcap files)
# * [optional] (a directory that contains custom/local python modules)
BASE_DIR        = ''

# Enviromental settings
JVM_MEMORY_SIZE = '4192m'

WEKA_ROOT          = os.path.join(BASE_DIR   ,'weka-3-7-5')
#WEKA_ROOT		   = '/Applications/weka-3-8-4-azul-zulu.app/Contents/Java/'
WEKA_JAR           = os.path.join(WEKA_ROOT  ,'weka.jar')
PCAP_ROOT          = os.path.join(BASE_DIR   ,'pcap-logs')

CACHE_DIR          = './cache'


### Sanity
def sanity():
    if not os.path.exists(WEKA_JAR):
        print('Weka does not exist in path: '+str(WEKA_JAR))
        print('Please install Weka properly.')
        #sys.exit()

    if BASE_DIR == '':
        print("!!!!")
        print("Please open config.py and set your BASE_DIR.")
        #sys.exit()


sanity()
###
