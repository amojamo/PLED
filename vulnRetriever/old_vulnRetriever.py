from lxml import html
import requests
import csv
from urllib.request import urlopen
import codecs
import time
import datetime
import re
import sys
import argparse
import configparser
from ares import CVESearch
from pymongo import MongoClient
from src.scanexploit import scanExploit
from src.mongo import DB
from src.csv import load_csv
from src.config import get_config

VERBOSE = 1
QUICKSCAN = 0
EXPLOITID = 0
UPDATER = 0
COUNTER = 0

#Get Arguments when running the script
parser = argparse.ArgumentParser(prog="vulnRetriever.py")
parser.add_argument('-q',
	'--quick', 
	dest="quickscan",
	help="Only scan the ids that are not already scanned",
	default=False,
	action="store_true")
parser.add_argument('-u',
	'--update',
	dest="updater",
	help="Check for new vulnerabilities",
	default=False,
	action="store_true")
parser.add_argument('-s',
	'--silent',
	dest="silent",
	help="Run without verbose",
	default=True,
	action="store_true")
parser.add_argument('-i',
	'--id',
	dest='id',
	help='Exploitdb id',
	default=EXPLOITID)

arguments = parser.parse_args()

QUICKSCAN = arguments.quickscan
VERBOSE = arguments.silent
EXPLOITID = arguments.id
UPDATER = arguments.updater

config = configparser.ConfigParser()
config.read('config/vulnRetriever.ini')
#Header since exploitdb dont like the python request UA
HEADER = { 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36' }

#Constant values set from vulnRetriever.conf
CHECKFILE = config['SCRAPING']['Checkfile']
CSVURL = config['EXPLOIT-DB.COM']['Csvurl']
EXPLOITURL = config['EXPLOIT-DB.COM']['Exploiturl']
MONGO_IP = config['DATABASE']['Mongo_ip']
MONGO_USER = config['DATABASE']['Mongo_user']
MONGO_PW = config['DATABASE']['Mongo_pw']
MONGO_DATABASE 	= config['DATABASE']['Mongo_database']
MONGO_COLLECTION = config['DATABASE']['Mongo_collection']
#From what year the search should start from
START_DATE = config['SETTINGS']['StartDate']
#check that date is correct in config to avoid errors later on
pattern = re.compile("^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01])$")
if not pattern.match(str(START_DATE)):
	sys.exit("Wrong start date syntax needs to be (yyyy-mm-dd)")


#Add verbose and run with -v argument
def verbose(text):
    if VERBOSE:
        print(text, end='\r')

#The main scanning function, returns
#True or False based on if an app was added
def scanExploit(exploit, id):
	cveData = ''
	#empty json data
	vulnData = {}
	#the url we want to check
	url = EXPLOITURL + id
	#Request the page with the selected headers
	page = requests.get(url, headers=HEADER)
	time.sleep(0.1)
	tree = html.fromstring(page.content)
	#What to look for on the page, that says if it has app or not
	#Look in html anchor for href with /apps/ in it
	#Example: <a href="/apps/786c8d62bf18c6c88d2d82a9443cd1e1-httpd-2.0.44.tar.gz">                                    
	hasapp = tree.xpath("//a[re:match(@href, '/apps/')]", 
	        namespaces={"re": "http://exslt.org/regular-expressions"})
	#Checks if the exploit is verified, using the checkmark class 
	isverified = tree.xpath("//i[contains(@class, 'mdi-check')]")
	if hasapp and isverified:
		vulnData['application_name'] = exploit[2]
		vulnData['exploitdb_id'] = id
		vulnData['type'] = exploit[5]
		vulnData['platform'] = exploit[6]
		vulnData['published_date'] = exploit[3]
		vulnData['added_date'] = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d')

		#if the page has an app, scan all the anchors
		#anchors are normally where hrefs are located
		#Since both the app and the cve is found in href this is what we need
		links = tree.xpath('//a')
		for link in links:
			#Store the app url
			#here it is also possible to download the url directly and store elsewhere
			if '/apps/' in link.attrib['href']:
				vulnData['file_path'] = 'https://www.exploit-db.com' + link.attrib['href'].strip()
			if 'CVE' in link.attrib['href']:
				#CVE is link and text content is the CVE id
				#Example: 2014-6271
				vulnData['cve'] = 'CVE-' + link.text_content().strip()
				#using https://github.com/barnumbirr/ares
				#to get cve data
				#load in CVESearch object
				cve_search = CVESearch()
				cveData = cve_search.id(vulnData['cve'])
				#Sometimes the CVE has no data, so check for that
				if cveData:
					if 'summary' in cveData: vulnData['cve_summary'] = cveData.get('summary')
					if 'cvss' in cveData: vulnData['cvss'] = cveData.get('cvss')
					if 'cwe' in cveData: vulnData['cwe'] = cveData.get('cwe')
					if 'impact' in cveData: 
						vulnData['impact'] = cveData.get('impact')
					if 'msbulletin' in cveData:
						vulnData['msbulletin'] = cveData.get('msbulletin')
					if 'vulnerable_configuration_cpe_2_2' in cveData:
						vulnData['vulnerable_configuration'] = cveData.get('vulnerable_configuration_cpe_2_2')		
		if cveData:
			if collection.insert_one(vulnData).acknowledged == True:
				return True
			else:
				return False
	else:
		return False


#get collection from PLED mongo server
#Values are set in the constants
client = MongoClient('mongodb://' + MONGO_USER + ':' + MONGO_PW + '@' + MONGO_IP)
db = client[MONGO_DATABASE]
collection = db[MONGO_COLLECTION]

#Get CSV data from exploitdb git repo
#To see the available data check the CSV url
response = urlopen(CSVURL)
csvData = csv.reader(codecs.iterdecode(response, 'utf-8'))
#skip the headers
next(csvData)
#Data is sorted by date which is row 4 (index start at 0)
#This way the updater can go by the latest added date
csvData = sorted(csvData, key=lambda row: row[3])

csvData = list(csvData)
if not EXPLOITID:
	#Removing all data from before set startdate
	#only when not running in "id" mode
	csvData = [x for x in csvData if x[3] >= START_DATE]
inserted = 0
documents = (collection.find({}, {"_id": 0, "exploitdb_id": 1}))
if "exploitdb_id" in documents:
	inDatabase = list([document['exploitdb_id'] for document in documents])
else:
	inDatabase = list()

#Updater to run on an interval to see if a new app has bimport codecseen added
#Checks the latest date in the database and compares with dates in the CSV data
if UPDATER:
	verbose('Running in update mode\n')
	currentDates = collection.find({},{'_id':0, 'published_date':1})
	#Create list of all stored dates
	datelist = []
	for doc in currentDates:
		if 'published_date' in doc:
			datelist.append(doc.get('published_date'))
	if datelist:
		#Use max to retrieve the latest date
		latest = max(datelist)
		csvData = [x for x in csvData if x[3] >= latest]
		for exploit in csvData:
			id = exploit[0]
			if id not in inDatabase:
				if scanExploit(exploit, id): inserted = inserted + 1
				COUNTER = COUNTER + 1	
				verbose(str(COUNTER) + ' out of ' + str(len(csvData)) + ' checked, ' + str(inserted) + ' inserted')	
	else:
		print('No dates found, run in normal mode to populate database')
		quit()
#If an id is added as argument
#Scan just this exploit
elif EXPLOITID:
	verbose('Scanning id: ' + EXPLOITID + '\n')
	found = False
	for exploit in csvData:
		if EXPLOITID == exploit[0] and EXPLOITID not in inDatabase:
			found = True
			if scanExploit(exploit, EXPLOITID): 
				verbose('id: ' + EXPLOITID + ' inserted\n')
			else:
				verbose('id: ' + EXPLOITID + ' found but not inserted\n')
	if not found:
		verbose('id: ' + EXPLOITID + ' not found or already in database, maybe startdate in config is wrong ?\n')

#Quickscan uses a text file to store the scanned ids, so not to scan them again
#Makes it possible to interupt the program and start again without loosing progess
elif QUICKSCAN:
	verbose('Quickscan initiated\n')
	#Open the checkfile
	checked = open(CHECKFILE, 'r+')
	#Create list with the checked ids
	checklist = [line.rstrip() for line in checked]
	#The counter start where the program ended last
	startindex = len(checklist)
	COUNTER = startindex
	for exploit in csvData[startindex:]:
		#Id is the first item in the row
		id = exploit[0]
		if id not in checklist and id not in inDatabase:
			if scanExploit(exploit, id): inserted = inserted + 1
		COUNTER = COUNTER + 1
		checked.write(id + '\n')
		verbose(str(COUNTER) + ' out of ' + str(len(csvData)) + ' checked, ' + str(inserted) + ' inserted')	
		#Sleep for 0.1 secs to have some delay on the requests to exploitdb
	checked.close()

#Normal mode
else:
	verbose("Scanning for vulnerable applications, this may take som time!\n")
	verbose("Start date is: " + START_DATE + '\n')
	for exploit in csvData:
		id = exploit[0]
		if id not in inDatabase:
			if scanExploit(exploit, id): inserted = inserted + 1
			COUNTER = COUNTER + 1	
			verbose(str(COUNTER) + ' out of ' + str(len(csvData)) + ' checked, ' + str(inserted) + ' inserted')	
			

