import re
import sys
import argparse
from src.scanexploit import scanExploit
from src.mongo import DB
from src.csv import load_csv
from src.config import get_config
import time

VERBOSE = 1
QUICKSCAN = 0
EXPLOITID = 0
UPDATER = 0

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

CONFIG = get_config('SETTINGS')
#check that date is correct in config to avoid errors later on
pattern = re.compile("^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01])$")
if not pattern.match(str(CONFIG['startdate'])):
	sys.exit("Wrong start date syntax needs to be (yyyy-mm-dd)")


#Add verbose and run with -v argument
def verbose(text):
    if VERBOSE:
        print(text, end='\r')

#Get CSV data from exploitdb git repo
#To see the available data check the CSV url
csvData = load_csv('date')
if not EXPLOITID:
	#Removing all data from before set startdate
	#only when not running in "id" mode
	csvData = [x for x in csvData if x[3] >= CONFIG['startdate']]

#create mongodb object

db = DB()
documents = db.get_documents_matching('exploitdb_id')
inDatabase = list()
for doc in documents:
	if 'exploitdb_id' in doc:
		inDatabase.append(doc['exploitdb_id'])


#Counters
counter = 0
inserted = 0

#Updater to run on an interval to see if a new app has bimport codecseen added
#Checks the latest date in the database and compares with dates in the CSV data
if UPDATER:
	verbose('Running in update mode\n')
	currentDates = db.get_documents_matching('published_date')
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
			if exploit[0] not in inDatabase:
				data = scanExploit(exploit)
				if data:
					if db.insert(data): inserted = inserted + 1
			counter = counter + 1	
			verbose(str(counter) + ' out of ' + str(len(csvData)) + ' checked, ' + str(inserted) + ' inserted')	
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
			data = scanExploit(exploit)
			if data:
				if db.insert(data): 
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
	checked = open(CONFIG['checkfile'], 'r+')
	#Create list with the checked ids
	checklist = [line.rstrip() for line in checked]
	#The counter start where the program ended last
	startindex = len(checklist)
	counter = startindex
	for exploit in csvData[startindex:]:
		#Id is the first item in the row
		id = exploit[0]
		if id not in checklist and id not in inDatabase:
			data = scanExploit(exploit)
			if data:
				if db.insert(data): inserted = inserted + 1
		counter = counter + 1
		verbose(str(counter) + ' out of ' + str(len(csvData)) + ' checked, ' + str(inserted) + ' inserted')	
		checked.write(id + '\n')
	checked.close()

#Normal mode
else:
	verbose("Scanning for vulnerable applications, this may take som time!\n")
	verbose("Start date is: " + CONFIG['startdate'] + '\n')
	for exploit in csvData:
		id = exploit[0]
		if exploit[0] not in inDatabase:
			data = scanExploit(exploit)
			if data:
				if db.insert(data): inserted = inserted + 1
		counter = counter + 1	
		verbose(str(counter) + ' out of ' + str(len(csvData)) + ' checked, ' + str(inserted) + ' inserted')


