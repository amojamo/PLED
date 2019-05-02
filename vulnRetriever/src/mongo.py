from pymongo import MongoClient
from src.config import get_config

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

    def insert(self, json_data):
        if self.db.insert_one(json_data).acknowledged == True:
            return True
        else:
            return False

    def get_documents_matching(self, key, id=False):
        return (self.db.find({}, {"_id": id, key: 1}))

