from flask_login import UserMixin
from pymongo import MongoClient

class User(UserMixin):
    def __init__(self, nom, prenom, email, password):
        self.nom = nom
        self.prenom = prenom
        self.email = email
        self.password = password

    @staticmethod
    def from_dict(user_dict):
        return User(user_dict['nom'], user_dict['prenom'], user_dict['email'], user_dict['password'])
    

class DatabaseManager:
    @staticmethod
    def get_database():
        client = MongoClient('mongodb://localhost:27017/')
        return client['SecurityScanDB']

class Scan:
    @staticmethod
    def save_to_database(date_scan, domain_name, addresses_IP, object_resultat, port_ouvert, systèmes_actifs, services, vulnérabilités):
        db = DatabaseManager.get_database()
        scan_collection = db['scans']
        scan_collection.insert_one({
            'date_scan': date_scan,
            'domain_name': domain_name,
            'addresses_IP': addresses_IP,
            'object_resultat': object_resultat,
            'port_ouvert': port_ouvert,
            'systèmes_actifs': systèmes_actifs,
            'services': services,
            'vulnérabilités': vulnérabilités
        })


class Vulnerability:
    @staticmethod
    def save_to_database(id_vuln, nom_vuln, description, gravite, address_ip, port):
        db = DatabaseManager.get_database()
        vulnerability_collection = db['vulnerabilities']
        vulnerability_collection.insert_one({
            'id_vuln': id_vuln,
            'nom_vuln': nom_vuln,
            'description': description,
            'gravite': gravite,
            'address_ip': address_ip,
            'port': port
        })

