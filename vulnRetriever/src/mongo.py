from pymongo import MongoClient
from src.config import get_config

#Class for initializing the database client
class DB():
    def __init__(self):
        config = get_config('DATABASE')
        self.ip = config['mongo_ip']
        self.user = config['mongo_user']
        self.pw = config['mongo_pw']
        self.database = config['mongo_database']
        self.collection = config['mongo_collection']
        #load database
        client = MongoClient('mongodb://' + self.user + ':' + self.pw + '@' + self.ip)
        db = client[self.database]
        self.db = db[self.collection]

    #insert into the database
    # @param json_data  - data to insert into database
    def insert(self, json_data):
        if self.db.insert_one(json_data).acknowledged == True:
            return True
        else:
            return False
    #Get a document that matches the key
    # @param key  - key to search for
    # @param id - if id should be present in the result, default is false
    def get_documents_matching(self, key, id=False):
        return (self.db.find({}, {"_id": id, key: 1}))

