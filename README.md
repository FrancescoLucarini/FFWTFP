# FFWTFP
Waf fuzzer and bypasser with proxy written in python2, at the end of every operation will have an output in .html format with a report of the work. This version is under development, and the next year I'll release in python3

Installation:

git clone https://github.com/FrancescoLucarini/FFWTFP/

cd FFWTFP/

pip install -r requirements.txt

#You need to use pip

#if the system says: pip command not found

#try this: sudo apt-get install python-pip

#if the requirements installation give u problem, it's because u don't have some dependencies

#so try: pip install PrettyTable

Usage&Docu:

fuzz                check which symbols and keywords are allowed by the WAF.
bypass              sends payloads from the database to the target.
insert-fuzz         add a fuzzing string
insert-bypass       add a payload to the bypass list
set-db              use another database file. Useful to share the same database with others.

optional arguments:
-h, --help            show this help message and exit
-v, --version         show program's version number and exit


python main.py (-h) (-v) [fuzz , bypass, insert-fuzz...] and a lot of other useful stuff that u can see in main.py first 50 lines

Example:


Fuzz:

python main.py fuzz -u "http://www.target.com/index.php?id=FUZZ" -c "phpsessid=value" -t [xss|sql] -o output.html 


Bypass:

python main.py bypass -u "http://www.target.com/index.php"  -p "Name=PAYLOAD&Submit=Submit" -c "phpsessid=value" -t [xss|sql] -o output.html
