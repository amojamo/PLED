import csv
import codecs
from urllib.request import urlopen
from src.config import get_config

def load_csv(sort):
    switcher = {
        'id': 0,
        'file': 1,
        'description': 2,
        'date': 3,
        'author': 4,
        'type': 5,
        'platform': 6,
        'port': 7       
    }
    #Get CSV data from exploitdb git repo
    #To see the available data check the CSV url
    config = get_config('CSV')
    response = urlopen(config['csvurl'])
    csvData = csv.reader(codecs.iterdecode(response, 'utf-8'))
    #skip the headers
    next(csvData)
    #Data is sorted by date which is row 4 (index start at 0)
    #This way the updater can go by the latest added date
    csvData = sorted(csvData, key=lambda row: row[switcher.get(sort, 3)])

    return list(csvData)