import uuid
import requests
import socket
import time 
from flask import Flask,flash, render_template, request, session, redirect, url_for,jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from dateutil.parser import isoparse
import datetime
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import bcrypt 
import json
import os
import subprocess
import re
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from functools import wraps
from xml.etree import ElementTree as ET


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'static/images'

# MongoDB Configuration
app.config['MONGO_URI'] = 'mongodb://localhost:27017/SecurityScanDB'


# Initialize PyMongo
mongo = PyMongo(app)
collection = mongo.db['vulnerability_details']  # Remplacez 'vulnerability_details' par le nom de votre collection
scans_collection = mongo.db['scans']  # Use your existing 'scans' collection

# Initialiser Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id, email, role):
        self.id = user_id
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({'user_id': user_id})
    if user_data:
        return User(user_data['user_id'], user_data['email'], user_data['role'])
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            print("User not authenticated")
            return redirect(url_for('login'))
        if current_user.role != 'admin':
            print(f"User {current_user.email} does not have admin role")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Fonction pour vérifier les mots de passe avec bcrypt
def verify_password(stored_password, provided_password):
    # Assurez-vous que le mot de passe stocké est correctement encodé en bytes
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":
        nom = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        terms_accepted = 'terms' in request.form

        # Liste pour collecter les erreurs
        errors = []

        # Vérification que tous les champs sont remplis
        if not nom or not email or not password or not role or not terms_accepted:
            errors.append("All fields are required and you must accept the terms.")

        # Validation du format de l'email
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email):
            errors.append("Invalid email format.")

        # Validation du nom (par exemple, que le nom ne contient que des lettres et des espaces)
        name_regex = r'^[A-Za-z\s]+$'
        if not re.match(name_regex, nom):
            errors.append("Name must contain only letters and spaces.")

        # Vérification si l'email existe déjà
        existing_user = mongo.db.users.find_one({'email': email})
        if existing_user:
            errors.append("An account with this email already exists.")

        # Si des erreurs existent, les retourner à l'interface
        if errors:
            return render_template("register.html", errors=errors)

        # Hachage du mot de passe
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        user_data = {
            'nom': nom,
            'email': email,
            'password': hashed_password.decode(),
            'role': role,
            'terms_accepted': terms_accepted
        }

        # Mise à jour ou création de l'utilisateur
        mongo.db.users.update_one(
            {'email': email},  # Critère de recherche
            {'$set': user_data},  # Données à mettre à jour
            upsert=True  # Insère le document s'il n'existe pas
        )

        # Connexion de l'utilisateur après la mise à jour/inscription
        user = mongo.db.users.find_one({'email': email})
        session['user_id'] = str(user['_id'])  # Convertir ObjectId en chaîne
        session['role'] = user['role']
        return redirect(url_for('login'))

    return render_template("register.html")




@app.route('/', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = mongo.db.users.find_one({'email': email})

        if user:
            if verify_password(user['password'], password):
                user_obj = User(user['user_id'], user['email'], user['role'])
                login_user(user_obj)
                session['user_id'] = user['user_id']
                session['role'] = user['role']
                session['nom'] = user['nom']
                print(f"User authenticated: {user['email']} with role {user['role']}")
                return redirect(url_for('dashboard' if user['role'] == 'admin' else 'acceil'))
            else:
                message = "Invalid password."
                print(f"Failed login attempt: incorrect password for email {email}")
        else:
            message = "Email does not exist."
            print(f"Failed login attempt: email {email} not found")

        return render_template("login.html", message=message)

    return render_template("login.html")


@app.route('/submit_contact_form', methods=['POST'])
def submit_contact_form():
    # Traitement du formulaire ici
    return 'Formulaire soumis'


# Page d'accueil
@app.route("/acceil", methods=['GET', 'POST'])
def acceil():
    if request.method == 'POST':
        domain = request.form.get('domain')
        if domain:
            return redirect(url_for('vulnerabilities', domain=domain))
        else:
            error_message = "Veuillez spécifier un nom de domaine."
            return render_template('error.html', error_message=error_message)
    return render_template('Acceil.html')



def collect_information(domain, user_id):
    try:
        command = f"theHarvester -d {domain} -b all"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        output = stdout.decode('utf-8')
        ips, subdomains, emails = parse_theHarvester_output(output)

        # Mettre à jour ou insérer les informations du domaine
        mongo.db.domaines.update_one(
            {'user_id': user_id, 'domain': domain},  # Critère de recherche
            {'$set': {
                'ips': ips,
                'subdomains': list(set(subdomains)),
                'emails': emails,
                'timestamp': datetime.datetime.utcnow()
            }},
            upsert=True  # Insère le document s'il n'existe pas
        )

        return ips, subdomains, emails
    except subprocess.CalledProcessError as e:
        print("Error:", str(e))
        return [], [], []



# Fonction pour parser la sortie de theHarvester
def parse_theHarvester_output(output):
    ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", output)
    subdomains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b", output)
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", output)
    return ips, subdomains, emails

# Vulnerabilites
@app.route('/vulnerabilites', methods=['GET', 'POST'])
def vulnerabilities():
    if request.method == 'POST':
        domain = request.form.get('domain')
        user_id = session.get('user_id')  # Récupérer l'ID utilisateur de la session
        if domain and user_id:
            ips, subdomains, emails = collect_information(domain, user_id)  # Passer user_id
            unique_subdomains = list(set(subdomains))
            return render_template('vulnerabilities.html', domain=domain, ips=ips, subdomains=unique_subdomains, emails=emails)
        else:
            error_message = "Veuillez spécifier un nom de domaine."
            return render_template('error.html', error_message=error_message)
    return render_template('Acceil.html')




# Filtre Jinja2 pour la conversion de nouvelles lignes en balises <br>
def nl2br(value):
    return re.sub(r'(\r\n|\r|\n)', '<br>', value)

app.jinja_env.filters['nl2br'] = nl2br

# Fonction pour mettre à jour la bibliothèque SploitScan
def update_sploitscan():
    sploitscan_dir = '/home/kali/Desktop/CyberShield/SploitScan'
    try:
        result = subprocess.check_output(['git', 'pull'], cwd=sploitscan_dir).decode('utf-8')
        print(f"SploitScan update result: {result}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error updating SploitScan: {e}")
        return False



def extract_ports_and_versions(nmap_result):
    ports_and_versions = {}
    lines = nmap_result.splitlines()
    for line in lines:
        match = re.match(r'(\d+)/tcp\s+open\s+(\S+)', line)
        if match:
            port = match.group(1)
            version = match.group(2)
            ports_and_versions[port] = version
    return ports_and_versions

def extract_vulnerabilities(nmap_output, open_ports_dict):
    vulnerabilities = {}
    cve_matches = re.findall(r'(CVE-\d{4}-\d+)', nmap_output)
    for cve in cve_matches:
        if cve not in vulnerabilities:
            vulnerabilities[cve] = {
                'port': None,
                # Add additional details if needed
            }
    return vulnerabilities

@app.route('/scan_ips', methods=['POST'])
def scan_ips():
    ips = request.form.getlist('ips')
    domain_name = request.form.get('domain_name')

    scan_id = str(uuid.uuid4())
    scan_timestamp = datetime.datetime.now()

    results = {}
    open_ports = {}
    vulnerabilities = {}

    for ip in ips:
        if ip:
            nmap_script_path = "/usr/share/nmap/scripts/vulscan/vulscan.nse"
            nmap_command = ["sudo", "nmap", "-sV", "--script=" + nmap_script_path, ip]
            try:
                result = subprocess.check_output(nmap_command, stderr=subprocess.STDOUT, timeout=1800).decode('utf-8')
                results[ip] = result

                # Extract open ports and versions
                ports_and_versions = extract_ports_and_versions(result)
                open_ports[ip] = [{'port': port, 'version': version, 'status': 'open', 'service': version if version != 'unknown' else 'unknown'} for port, version in ports_and_versions.items()]

                # Extract vulnerabilities
                vulnerabilities[ip] = extract_vulnerabilities(result, ports_and_versions)

                # Insert results into MongoDB
                scan_result = {
                    'scan_id': scan_id,
                    'scan_timestamp': scan_timestamp,
                    'ip': ip,
                    'domain_name': domain_name,
                    'results': result,
                    'open_ports': open_ports[ip],
                    'vulnerabilities': vulnerabilities[ip]
                }

                # Insert into the scans collection
                scans_collection.insert_one(scan_result)

            except subprocess.CalledProcessError as e:
                results[ip] = f"Error: {e.output.decode('utf-8')}"
            except subprocess.TimeoutExpired:
                results[ip] = "Error: Command timed out"
            except Exception as e:
                results[ip] = f"Error: An unexpected error occurred: {str(e)}"

    # Save results to a JSON file
    with open(f'static/results_{scan_id}.json', 'w') as file:
        json.dump({
            'results': results,
            'domain_name': domain_name,
            'ips': ips,
            'open_ports': open_ports,
            'vulnerabilities': vulnerabilities
        }, file, indent=4)

    # Render results in a HTML template
    return render_template('scan_results.html', 
                           domain_name=domain_name,
                           ips=ips,
                           nmap_results=results,
                           open_ports=open_ports,
                           vulnerabilities=vulnerabilities)

@app.route('/scan_ports', methods=['POST'])
def scan_ports():
    ip = request.form.get('ip')
    domain = request.form.get('domain')
    ports = request.form.get('ports')  # Ensure ports are collected from the request
    user_id = session.get('user')

    if not ip or not ports or not domain:
        return "IP, ports, ou nom de domaine manquant", 400

    try:
        domain = domain.strip()

        # Mise à jour de la bibliothèque SploitScan
        if not update_sploitscan():
            return "Échec de la mise à jour de la bibliothèque SploitScan", 500

        scan_id = str(uuid.uuid4())
        port_list = [port.strip() for port in ports.split(',') if port.strip()]
        ports_str = ",".join(port_list)

        nmap_command = [
            'sudo', 'nmap', '-p', ports_str, '-A', '-O',
            '--script', 'vulscan/vulscan.nse,ftp-anon,ftp-brute', ip
        ]

        print(f"Commande exécutée : {' '.join(nmap_command)}")

        # Exécution de Nmap et récupération des résultats
        nmap_result = subprocess.check_output(nmap_command, stderr=subprocess.STDOUT).decode('utf-8')
        print(f"Résultat de Nmap :\n{nmap_result}")

        open_ports_dict = extract_ports_and_versions(nmap_result)
        vulnerabilities = extract_vulnerabilities(nmap_result, open_ports_dict)

        vulnerability_details_list = []

        for cve_id, details in vulnerabilities.items():
            # If port is not found in details, use the user-provided port
            port = details.get('port') or ports_str
            sploitscan_script = os.path.join('/home/kali/Desktop/CyberShield/SploitScan', 'sploitscan.py')

            if not os.path.exists(sploitscan_script):
                print(f"Erreur : sploitscan.py introuvable à {sploitscan_script}")
                continue

            sploitscan_command = ['python3', sploitscan_script, cve_id]
            print(f"Commande SploitScan exécutée : {' '.join(sploitscan_command)}")

            try:
                sploitscan_result = subprocess.check_output(sploitscan_command, stderr=subprocess.STDOUT).decode('utf-8')
                print(f"Résultat SploitScan pour {cve_id}:\n{sploitscan_result}")

                if not sploitscan_result.strip():
                    print(f"Aucune sortie de sploitscan.py pour le CVE {cve_id}")
                    continue

                parsed_results = parse_sploitscan_results(sploitscan_result, port, scan_id, ip, domain)
                if parsed_results:
                    vulnerability_details_list.append(parsed_results)
                else:
                    print(f"Échec de l'analyse des résultats de sploitscan.py pour le CVE {cve_id}")

            except subprocess.CalledProcessError as e:
                print(f"Erreur lors de l'exécution de sploitscan.py pour le CVE {cve_id} : {e}")

        print("Liste des détails de vulnérabilité :", vulnerability_details_list)

        # Mise à jour de la base de données MongoDB
        for vulnerability in vulnerability_details_list:
            mongo.db['vulnerability_details'].update_one(
                {
                    'scan_id': scan_id,
                    'ip': ip,
                    'cve_id': vulnerability.get('cve_id', 'N/A'),
                    'port': vulnerability.get('port', ports_str),  # Ensure correct port value
                    'domain': domain
                },
                {
                    '$set': {
                        'published': vulnerability.get('published', 'N/A'),
                        'base_score': vulnerability.get('base_score', 'N/A'),
                        'vector': vulnerability.get('vector', 'N/A'),
                        'description': vulnerability.get('description', 'N/A'),
                        'epss_score': vulnerability.get('epss_score', 'N/A'),
                        'epss_rank': vulnerability.get('epss_rank', 'N/A'),
                        'reports': vulnerability.get('reports', 'N/A'),
                        'severity': vulnerability.get('severity', 'N/A'),
                        'patch_priority': vulnerability.get('patch_priority', 'N/A'),
                        'references': vulnerability.get('references', []),
                        'port': vulnerability.get('port', ports_str)  # Ensure the correct port value is updated
                    }
                },
                upsert=True
            )

        return render_template('port_scan_results.html', open_ports_dict=open_ports_dict, vulnerability_details_list=vulnerability_details_list)

    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'exécution de Nmap : {e.output.decode('utf-8')}")
        return "Erreur lors de l'exécution de Nmap", 500

def parse_sploitscan_results(result, port, scan_id, ip, domain):
    parsed_results = {}
    try:
        def safe_search(pattern, text):
            match = re.search(pattern, text)
            return re.sub(r'\x1b\[[0-9;]*m', '', match.group(1).strip()) if match else 'N/A'

        parsed_results['cve_id'] = safe_search(r'CVE ID:\s*(CVE-\d{4}-\d+)', result)
        parsed_results['published'] = safe_search(r'Published:\s*([^\n]+)', result)
        parsed_results['base_score'] = safe_search(r'Base Score:\s*([^\n]+)', result)
        parsed_results['vector'] = safe_search(r'Vector:\s*([^\n]+)', result)
        parsed_results['description'] = safe_search(r'Description:\s*([^\n]+(?:\n\s+[^\n]+)*)', result)
        parsed_results['epss_score'] = safe_search(r'EPSS Score:\s*([^\n]+)', result)
        parsed_results['epss_rank'] = safe_search(r'Rank:\s*([^\n]+)', result)
        parsed_results['reports'] = safe_search(r'Reports:\s*([^\n]+)', result)
        parsed_results['severity'] = safe_search(r'Severity:\s*([^\n]+)', result)
        parsed_results['patch_priority'] = safe_search(r'Priority:\s*([^\n]+)', result)
        parsed_results['references'] = re.findall(r'https?://[^\s]+', result)
        
        # Ensure the port value is correctly assigned or defaults to 'N/A'
        parsed_results['port'] = port  # Use the provided port value
        parsed_results['domain'] = domain

        # Update MongoDB with vulnerability details
        mongo.db['vulnerability_details'].update_one(
            {
                'scan_id': scan_id,
                'ip': ip,
                'port': parsed_results.get('port', 'N/A'),  # Ensure the correct port value
                'domain': domain
            },
            {
                '$set': {
                    'cve_id': parsed_results.get('cve_id', 'N/A'),
                    'published': parsed_results.get('published', 'N/A'),
                    'base_score': parsed_results.get('base_score', 'N/A'),
                    'vector': parsed_results.get('vector', 'N/A'),
                    'description': parsed_results.get('description', 'N/A'),
                    'epss_score': parsed_results.get('epss_score', 'N/A'),
                    'epss_rank': parsed_results.get('epss_rank', 'N/A'),
                    'reports': parsed_results.get('reports', 'N/A'),
                    'severity': parsed_results.get('severity', 'N/A'),
                    'patch_priority': parsed_results.get('patch_priority', 'N/A'),
                    'references': parsed_results.get('references', []),
                    'port': parsed_results.get('port', 'N/A')
                }
            },
            upsert=True
        )

    except Exception as e:
        print(f"Error parsing results: {e}")

    return parsed_results



@app.route('/dashboard', methods=['GET'])
def dashboard():
    # Fetch total number of users
    total_users = mongo.db.users.count_documents({})

    # Fetch total number of vulnerabilities from the correct collection
    total_vulnerabilities = mongo.db.vulnerability_details.count_documents({})

    # Fetch total number of scans
    total_scans = mongo.db.scans.count_documents({})

    # Prepare data for rendering
    dashboard_data = {
        "total_users": total_users,
        "total_vulnerabilities": total_vulnerabilities,
        "total_scans": total_scans
    }

    return render_template('dashboard.html', data=dashboard_data)


@app.route('/vulnerabilities_dash', methods=['GET'])
def vulnerabilities_dash():
    # Récupérer les paramètres de filtrage (domaine, adresse IP, port)
    domain = request.args.get('filter_domain')
    ip = request.args.get('filter_ip')
    port = request.args.get('filter_port')
    
    # Construire la requête pour MongoDB
    query = {}
    if domain:
        query['domain'] = domain
    if ip and domain:
        query['ip'] = ip
    if port and ip:
        query['port'] = port

    # Récupérer les vulnérabilités depuis la base de données
    vulnerabilities = list(mongo.db.vulnerability_details.find(query))
    
    # Si aucune vulnérabilité n'est trouvée, afficher un message
    if not vulnerabilities:
        message = "No vulnerabilities found for the given filters."
    else:
        message = ""

    return render_template('vulnerabilities_dash.html', vulnerabilities=vulnerabilities, message=message)



#Manage Users Route
@app.route('/users')
@admin_required
def users():
    filter_name = request.args.get('filter_name')

    query = {"role": "user"}
    
    if filter_name:
        query['nom'] = {"$regex": filter_name, "$options": "i"}

    users = list(mongo.db.users.find(query))

    message = None
    if not users:
        message = "No users found matching your criteria."

    return render_template('users.html', users=users, message=message)

# Save User Route
@app.route('/save_user', methods=['POST'])
def save_user():
    if 'user_id' in session and session.get('role') == 'admin':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        action = request.form['action']
        if action == 'updateUser':
            user_id = request.form['user_id']
            mongo.db.users.update_one(
                {'user_id': user_id},
                {'$set': {
                    'nom': username,
                    'email': email,
                    'password': hashed_password.decode('utf-8')
                }}
            )
            flash('User has been successfully updated!', 'success')
        else:
            user_id = str(uuid.uuid4())
            picture = request.files['uploadFile']
            picture_filename = secure_filename(picture.filename) if picture else 'default.jpg'
            if picture:
                picture.save(os.path.join(app.config['UPLOAD_FOLDER'], picture_filename))

            mongo.db.users.insert_one({
                'user_id': user_id,
                'nom': username,
                'email': email,
                'password': hashed_password.decode('utf-8'),
                'role': 'user',
                'terms_accepted': True,
                'picture': picture_filename
            })
            flash('User has been successfully added!', 'success')
        
        return redirect(url_for('users'))
    
    flash('You must be logged in as an admin to perform this action.', 'error')
    return redirect(url_for('login'))

# Edit User Route
@app.route("/edit_user", methods=['GET', 'POST'])
def edit_user():
    if 'user_id' in session and session.get('role') == 'admin':
        user_id = request.args.get('user_id')
        
        if not user_id:
            flash('No user ID provided.', 'error')
            return redirect(url_for('users'))
        
        user = mongo.db.users.find_one({'user_id': user_id})
        
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('users'))
        
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            mongo.db.users.update_one(
                {'user_id': user_id},
                {'$set': {
                    'nom': username,
                    'email': email,
                    'password': hashed_password.decode('utf-8')
                }}
            )
            flash('User has been successfully updated!', 'success')
            return redirect(url_for('users'))
        
        return render_template("edit_user.html", user=user)
    
    flash('You must be logged in as an admin to perform this action.', 'error')
    return redirect(url_for('login'))

# Delete User Route
@app.route("/delete_user", methods=['GET'])
def delete_user():
    if 'user_id' in session and session.get('role') == 'admin':
        user_id = request.args.get('user_id')
        mongo.db.users.delete_one({'user_id': user_id})
        flash('User has been successfully deleted!', 'success')
        return redirect(url_for('users'))
    
    flash('You must be logged in as an admin to perform this action.', 'error')
    return redirect(url_for('login'))

@app.route('/manage_roles', methods=['GET', 'POST'])
@admin_required
def manage_roles():
    if request.method == 'POST':
        user_id = request.form['user_id']
        new_role = request.form['role']
        mongo.db.users.update_one({'user_id': user_id}, {'$set': {'role': new_role}})
        
        # Add a flash message for success
        flash('User role updated successfully!', 'success')

        return redirect(url_for('manage_roles'))

    users = list(mongo.db.users.find({}))
    return render_template('manage_roles.html', users=users)



# Page de contact
@app.route("/contact")
def contact():
    return render_template("contact.html")



@app.route('/services')
def services():
    return render_template('services.html')


@app.route('/contactdash')
def contactdash():
    return render_template('contactdash.html')





@app.route('/report', methods=['GET'])
def report():
    # Récupérer les domaines distincts
    domains = mongo.db.domaines.distinct('domain')

    return render_template('report.html', domains=domains)


@app.route('/domain/<domain>', methods=['GET'])
def domain_details(domain):
    # Récupérer les données du domaine depuis la base de données
    domain_data = mongo.db.domaines.find_one({'domain': domain})
    if not domain_data:
        return f"Domain '{domain}' not found in database.", 404

    # Pour le débogage, vous pouvez imprimer les données récupérées
    print(f"Domain Data: {domain_data}")

    return render_template('domain_details.html', domain=domain_data)



def format_timestamp(port_data):
    """Formate le timestamp pour un port."""
    timestamp = port_data['timestamp']
    if timestamp != 'N/A':
        try:
            # Si le timestamp est en format UNIX, le convertir
            formatted_time = datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            # Si le timestamp n'est pas un entier, le retourner tel quel
            formatted_time = timestamp
        port_data['timestamp'] = formatted_time
    return port_data

@app.route('/ip_details/<ip>', methods=['GET'])
def ip_details(ip):
    """Display scan details for a specific IP, including open ports with status, version, and service name."""
    
    # Define insecure ports with their icons
    insecure_ports = {
        '21': 'fa-file-transfer',
        '23': 'fa-terminal',
        '25': 'fa-envelope',
        '53': 'fa-server',
        '67': 'fa-network-wired',
        '68': 'fa-network-wired',
        '69': 'fa-file-transfer',
        '80': 'fa-globe',
        '110': 'fa-envelope',
        '143': 'fa-envelope',
        '161': 'fa-network-wired',
        '162': 'fa-network-wired',
        '3306': 'fa-database',
        '3389': 'fa-desktop',
        '5900': 'fa-desktop',
        '6379': 'fa-database',
        '8080': 'fa-globe',
        '9200': 'fa-database',
        '27017': 'fa-database',
        '5000': 'fa-server',
        '22': 'fa-lock',
        '1433': 'fa-database',
        '1434': 'fa-database'
    }

    # Search for scan results for the IP
    scan = scans_collection.find_one({'ip': ip})  # Updated to use scans_collection

    if not scan:
        return f"Scan results for IP '{ip}' not found.", 404

    # Get open ports and scan results
    open_ports = scan.get('open_ports', [])
    scan_timestamp = scan.get('scan_timestamp', 'N/A')  # Updated to use 'scan_timestamp' field

    # Collect port information
    ports = []
    if open_ports:
        for port_info in open_ports:
            port_number = port_info.get('port', 'Unknown')
            is_insecure = port_number in insecure_ports
            port_data = {
                'port': port_number,
                'status': port_info.get('status', 'Unknown'),
                'version': port_info.get('version', 'Unknown'),
                'service': port_info.get('service', 'Unknown'),  # Include service name
                'is_insecure': is_insecure,
                'icon': insecure_ports.get(port_number, '')  # Get icon for the port
            }
            ports.append(port_data)

    return render_template('ip_details.html', ip=ip, ports=ports, scan_timestamp=scan_timestamp)

# Fonction utilitaire pour extraire la version du scan_results
def extract_version(scan_results, port):
    """Extrait la version du résultat de scan basé sur le port."""
    pattern = re.compile(rf'{port}/tcp\s+open\s+([\w\s/]+)', re.MULTILINE)
    match = pattern.search(scan_results)
    return match.group(1).strip() if match else 'Unknown'



@app.route('/port_vulnerabilities/<ip>/<port>', methods=['GET'])
def port_vulnerabilities(ip, port):
    """Affiche les détails des vulnérabilités pour un port spécifique."""
    
    vulnerability_details = list(mongo.db.vulnerability_details.find({'ip': ip, 'port': port}))

    return render_template('port_vulnerabilities.html', ip=ip, port=port, vulnerabilities=vulnerability_details)

collection = mongo.db['vulnerability_details']  # Remplacez 'vulnerability_details' par le nom de votre collection

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    data = []
    cursor = collection.find({})
    for document in cursor:
        try:
            # Extraire et convertir EPSS Score
            epss_score_str = document.get('epss_score', '0.0% Probability of exploitation.')
            if '%' in epss_score_str:
                epss_score = float(epss_score_str.split('%')[0].strip()) / 100
            else:
                epss_score = 0.0
        except ValueError:
            epss_score = 0.0
        
        try:
            # Extraire et convertir Base Score
            base_score_str = document.get('base_score', '0.0')
            if 'N/A' not in base_score_str and base_score_str.split()[0].replace('.', '', 1).isdigit():
                base_score = float(base_score_str.split()[0])
            else:
                base_score = 0.0
        except ValueError:
            base_score = 0.0
        
        data.append({
            'cve_id': document.get('cve_id', ''),
            'epss_score': epss_score,
            'base_score': base_score
        })
    return jsonify(data)





# Censys API credentials
API_ID = '2411a566-8067-4572-9df9-8d112df09e1d'
API_SECRET = 'tAmuKzLZQHd6Ftf2qsoNIVOLdfOHJdRK'

# Step 1: Fetch all open ports from the scans collection
all_open_ports = []
for scan in scans_collection.find():
    for port_info in scan['open_ports']:
        all_open_ports.append({
            'ip': scan['ip'],
            'port': port_info['port'],
            'scan_id': scan['scan_id']
        })

# Step 2: Fetch all vulnerable ports from the vulnerability_details collection
vulnerable_ports = set()
for vuln in mongo.db.vulnerability_details_collection.find():
    vulnerable_ports.add((vuln['ip'], vuln['port']))

# Step 3: Identify non-vulnerable ports
non_vulnerable_ports = [p for p in all_open_ports if (p['ip'], p['port']) not in vulnerable_ports]

# Step 4: Call the Censys API for each non-vulnerable port to check for new vulnerabilities
newly_detected_vulnerabilities = []  # List to store new vulnerabilities

for port_entry in non_vulnerable_ports:
    ip = port_entry['ip']
    port = port_entry['port']

    # Call Censys API for each IP and port
    url = f'https://search.censys.io/api/v2/hosts/{ip}'
    headers = {'Accept': 'application/json'}

    response = requests.get(url, auth=(API_ID, API_SECRET), headers=headers)

    if response.status_code == 200:
        result = response.json()
        # Check if the port is now vulnerable
        for service in result.get('result', {}).get('services', []):
            if service['port'] == int(port):
                # If the port is now vulnerable, prepare new vulnerability data
                new_vulnerability_data = {
                    'cve_id': 'NEW_CVE',  # Extract from API if possible
                    'description': 'New vulnerability detected',
                    'epss_score': 0.5,  # Example score, adjust as needed
                    'epss_rank': 1000,
                    'severity': 'High',  # Example severity, adjust as needed
                    'patch_priority': 'A',
                    'port': str(port),
                    'ip': ip
                }

                # Store the new vulnerability in the list
                newly_detected_vulnerabilities.append(new_vulnerability_data)

                # Update MongoDB with new vulnerability data
                mongo.db.vulnerability_details_collection.update_one(
                    {"ip": ip, "port": port},
                    {"$set": new_vulnerability_data},
                    upsert=True
                )

                # Also update the scans collection
                mongo.db.cans_collection.update_one(
                    {"scan_id": port_entry['scan_id']},
                    {"$set": {
                        f"vulnerabilities.{port}": new_vulnerability_data
                    }}
                )
    else:
        print(f"Error: {response.status_code} - {response.text}")

# Store the newly detected vulnerabilities in a global variable
app.newly_detected_vulnerabilities = newly_detected_vulnerabilities

@app.route('/vulnerable_ports')
def get_vulnerable_ports():
    # Fetch updated ports with vulnerabilities
    updated_vulnerable_ports = list(mongo.db.vulnerability_details_collection.find({
        "severity": {"$in": ["Medium", "High", "Critical"]}
    }))
    
    # Return the count of new vulnerabilities
    return jsonify(new_vulnerabilities_count=len(updated_vulnerable_ports))

@app.route('/vulnerable_ports_view')
def vulnerable_ports_view():
    # Fetch updated ports with vulnerabilities
    updated_vulnerable_ports = list(mongo.db.vulnerability_details_collection.find({
        "severity": {"$in": ["Medium", "High", "Critical"]}
    }))
    
    # Pass the updated vulnerable ports to the template
    return render_template('vulnerable_ports.html', ports=updated_vulnerable_ports, new_ports=app.newly_detected_vulnerabilities)




@app.route('/about', methods=['GET'])
def about():
    filter_ip = request.args.get('filter_ip', '')
    filter_port = request.args.get('filter_port', '')
    filter_domain = request.args.get('filter_domain', '')

    query = {}
    if filter_ip:
        query['ip'] = filter_ip
    if filter_port:
        query['port'] = filter_port
    if filter_domain:
        query['domain'] = filter_domain

    # Effectuer la recherche dans MongoDB
    vulnerabilities = list(collection.find(query))

    # Vérifiez si aucune vulnérabilité n'a été trouvée
    no_results = len(vulnerabilities) == 0

    return render_template('about.html', vulnerabilities=vulnerabilities, no_results=no_results)


# ### Dashbord:
@app.route('/domains', methods=['GET'])
def domains():
    # Récupérer les domaines distincts
    domains = mongo.db.domaines.distinct('domain')
    return render_template('domains.html', domains=domains)


@app.route('/subdomains')
def subdomains():
    # Récupérez les documents de la collection
    domaines = mongo.db.domaines.find()
    
    # Formatez les données en une structure de dictionnaire pour un affichage en arbre
    domain_tree = {}
    for domaine in domaines:
        domain = domaine['domain']
        subdomains = domaine.get('subdomains', [])
        domain_tree[domain] = subdomains
    
    return render_template('subdomains.html', domain_tree=domain_tree)



# Route pour afficher le formulaire de scan
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)


