import copy
from prettytable import PrettyTable
from progressbar import *
import ssl
import codecs
from time import sleep
import urllib
import urllib2
import argparse
from argparse import RawTextHelpFormatter
import sqlite3
import re
import string
import cgi
from fireplace_fuzzer import fireFuzz
from fireplace_payloads import firePayload
import random
from db.db import getPayload, setPayload, getFuzz, setFuzz
from db.setDB import testConnection, setDatabase
def getArguments():
    
    parser = argparse.ArgumentParser(description='''
    
     ▄▀▀▀█▄    ▄▀▀▀█▄    ▄▀▀▄    ▄▀▀▄  ▄▀▀▀█▀▀▄  ▄▀▀▀█▄    ▄▀▀▄▀▀▀▄ 
    █  ▄▀  ▀▄ █  ▄▀  ▀▄ █   █    ▐  █ █    █  ▐ █  ▄▀  ▀▄ █   █   █ 
    ▐ █▄▄▄▄   ▐ █▄▄▄▄   ▐  █        █ ▐   █     ▐ █▄▄▄▄   ▐  █▀▀▀▀  
     █    ▐    █    ▐     █   ▄    █     █       █    ▐      █      
     █         █           ▀▄▀ ▀▄ ▄▀   ▄▀        █         ▄▀       
    █         █                  ▀    █         █         █         
   ▐         ▐                       ▐         ▐         ▐         

From FireWall To FirePlace Version=>1.0 Author = Francesco Lucarini
Example Usage:
fuzz:\n\tpython main.py fuzz -u "http://www.target.com/index.php?id=FUZZ" \n\t-c "phpsessid=value" -t xss -o output.html 

bypass:\n\tpython main.py bypass -u "http://www.target.com/index.php" \n\t-p "Name=PAYLOAD&Submit=Submit" \n\t-c "phpsessid=value" -t xss -o output.html

insert-fuzz:\n\tpython main.py insert-fuzz -i select -e select -t sql
''',formatter_class=RawTextHelpFormatter, version='FFWTFP 1.0')
    subparser = parser.add_subparsers(help='Which function do you want to use?\n\n', dest='mode')
    attack_fuzz_parser = subparser.add_parser("fuzz",help='check which symbols and keywords are allowed by the WAF.')
    attack_payload_parser = subparser.add_parser("bypass",help='sends payloads from the database to the target.')
    insert_fuzz_parser = subparser.add_parser("insert-fuzz",help='add a fuzzing string')
    insert_bypass_parser = subparser.add_parser("insert-bypass",help='add a payload to the bypass list')
    set_db_parser = subparser.add_parser("set-db",help='use another database file. Useful to share the same database with others.')
    
    ## attack parser ##
    attack_payload_parser.add_argument('-u',metavar='URL',help='Target URL (e.g. "www.target.com/index.php?id=PAYLOAD")\nNote: specify the position of the payload with the keyword PAYLOAD',required=True)
    attack_payload_parser.add_argument('-p',metavar='POST PARAMETER',help='Send payload through post parameter ',required=False)    
    attack_payload_parser.add_argument('-c',metavar='COOKIE',help='HTTP Cookie Header',required=False)
    attack_payload_parser.add_argument('-t',metavar='TYPE',choices=['sql','xss'],help='Type of payload [sql|xss]', required=True)
    attack_payload_parser.add_argument('-d',metavar='DELAY',default='0',help="Wait the given delay time between each request [default=0]",required=False)
    attack_payload_parser.add_argument('-w',metavar='WAF',help='Send payloads of certain WAF [default=generic]', required=False)
    attack_payload_parser.add_argument('-o',metavar='OUTPUT FILE',help="Save output to .html file",required=False)
    attack_payload_parser.add_argument('--proxy',metavar='PROXY',help='Use a proxy. Format: IP:PORT', required=False)
    attack_payload_parser.add_argument('--prefix',metavar='PROXY',help='Add a prefix to every payload.', required=False)
    attack_payload_parser.add_argument('--postfix',metavar='PROXY',help='Add a postfix to every payload.', required=False)
    
    ## attack fuzz ##
    attack_fuzz_parser.add_argument('-u',metavar='URL',help='Target URL (e.g. "www.target.com/index.php?id=FUZZ")\nNote: specify the position of the fuzz with the keyword FUZZ',required=True)
    attack_fuzz_parser.add_argument('-p',metavar='POST PARAMETER',help='Send fuzz through post parameter ',required=False)
    attack_fuzz_parser.add_argument('-c',metavar='COOKIE',help='HTTP Cookie Header',required=False)
    attack_fuzz_parser.add_argument('-t',metavar='TYPE',choices=['sql','xss'],help='Type of payload [sql|xss]', required=True)
    attack_fuzz_parser.add_argument('-d',metavar='DELAY',default=0,help="Wait the given delay time between each request [default=0]",required=False)
    attack_fuzz_parser.add_argument('-o',metavar='OUTPUT FILE',help="Save output to .html file",required=False)
    attack_fuzz_parser.add_argument('--proxy',metavar='PROXY',help='Use a proxy. Format: IP:PORT', required=False)
    attack_fuzz_parser.add_argument('--prefix',metavar='PROXY',help='Add a prefix to every fuzz.', required=False)
    attack_fuzz_parser.add_argument('--postfix',metavar='PROXY',help='Add a postfix to every fuzz.', required=False)
    
    ## insert bypass parser ##
    insert_bypass_parser.add_argument('-i',metavar='INPUT',help='Payload to insert',required=True)
    insert_bypass_parser.add_argument('-t',metavar='TYPE',choices=['sql','xss'], help='Type of payload [sql|xss]',required=True)
    insert_bypass_parser.add_argument('-w',metavar='WAF',help='WAF that was bypassed with this payload', required=False)
    
    ## insert fuzz parser ##
    insert_fuzz_parser.add_argument('-i',metavar='INPUT',help='Fuzz to insert',required=True)
    insert_fuzz_parser.add_argument('-e',metavar='EXPECTED',help='Expected output from the target site. Use this option if input is encoded or something like that.',required=False)
    insert_fuzz_parser.add_argument('-t',metavar='TYPE',choices=['sql','xss'], help='Type of payload [sql|xss]',required=True)

    ## set database parser ##
    set_db_parser.add_argument('-p',metavar='PATH',help='Path to sqlite database. The default location is "db/db.sqlite"',required=True)
    
    args = parser.parse_args()


    if args.mode == 'bypass':
        url = args.u
        post = args.p
        cookie = args.c
        type = args.t.lower()
        delay = args.d
        waf = args.w
        if waf is not None:
            waf = waf.lower()
        outputFile = args.o
        proxy = args.proxy
        if proxy is None:
            proxy = ''
        prefix = args.prefix
        if prefix is None:
            prefix = ''
        postfix = args.postfix
        if postfix is None:
            postfix = ''
        return ['bypass', url, post, cookie, type, delay, waf, outputFile, proxy, prefix, postfix]
    
    elif args.mode == 'fuzz':
        url = args.u
        post = args.p
        cookie = args.c
        type = args.t.lower()
        delay = args.d
        outputFile = args.o
        proxy = args.proxy
        if proxy is None:
            proxy = ''
        prefix = args.prefix
        if prefix is None:
            prefix = ''
        postfix = args.postfix
        if postfix is None:
            postfix = ''
        return ['fuzz', url, post, cookie, type, delay, outputFile, proxy, prefix, postfix] 
    
    elif args.mode == 'insert-bypass':
        input = args.i
        type = args.t
        waf = args.w
        if waf is not None:
            waf = waf.lower()
        return ['insert-bypass', input, type, waf]
    
    elif args.mode == 'insert-fuzz':
        input = args.i
        if args.e is not None:
            expected = args.e
        else:
            expected = args.i
        type = args.t
        return ['insert-fuzz', input, expected, type]
        
    elif args.mode == 'set-db':
        path = args.p
        return ['set-db', path]

def setHeaders(cookie):
    """
        :Description: This function sets the cookie for the requests. 

        :param cookie:  A Cookie String
        :type cookie: String
        :todo: Add also other header
		
    """
    if cookie is not None:
        header.append(['Cookie',cookie])
def extractParams(input):
    """
        :Description: Takes the '-p' input and splits it into individual parameter

        :param input: POST Parameter
        :type input: String

        :return: Dictionary with the parameter as elements
        :note: This function is required to prepare the parameter for the firePayload() or fireFuzz() function
		
    """
    if input is None:
        return None
    input = input.split('&')
    params = {}
    for item in input:
        params[item.split('=',1)[0]] = item.split('=',1)[1]
    return params
arguments = getArguments()

if arguments[0] == 'bypass':
    arguments.pop(0) # delete the string that indicates what function to use
    url, post, cookie, type, delay, waf, outputFile, proxy, prefix, postfix = arguments
    payload = getPayload(type, waf) # get strings from db
    header = []
    setHeaders(cookie)
    post = extractParams(post)
    firePayload(type, payload, url, post, header, delay, outputFile, proxy, prefix, postfix)
        
elif arguments[0] == 'fuzz':
    arguments.pop(0) # delete the string that indicates what function to use
    url, post, cookie, type, delay, outputFile, proxy, prefix, postfix = arguments
    fuzz = getFuzz(type) # get strings from db
    header = []
    setHeaders(cookie)
    post = extractParams(post)
    fireFuzz(type, fuzz, url, post, header, delay, outputFile, proxy, prefix, postfix)
        
elif arguments[0] == 'insert-bypass':
    arguments.pop(0)
    input, type, waf = arguments
    setPayload(input, type, waf)
    
elif arguments[0] == 'insert-fuzz':
    arguments.pop(0)
    input, expected, type = arguments
    setFuzz(input, expected, type)

elif arguments[0] == 'set-db':
    arguments.pop(0)
    path = arguments[0]
    if (testConnection(path) == 1):
        setDatabase(path)
        print "Database sucessfully changed!"
