# config.py
from pymongo import MongoClient

# URL de connexion à MongoDB
mongo_uri = 'mongodb://localhost:27017/'

# Créer une instance de MongoClient
client = MongoClient(mongo_uri)

# Sélectionner la base de données
db = client['SecurityScanDB']

