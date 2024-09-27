import os
import uuid
import re
import subprocess
from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import sublist3r
import requests
import nmap
import datetime
app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = os.urandom(24)

# Fonction de connexion à la base de données MongoDB
def connect_to_database():
    client = MongoClient('mongodb://localhost:27017/')  # Connexion locale par défaut
    return client['SecurityScanDB']  # Remplacez 'votre_base_de_données' par le nom de votre base de données

# Connexion à la base de données MongoDclient = MongoClient('mongodb://localhost:27017/')
db = client['SecurityScanDB']

# Clé API du NVD
api_key = 'YOUR_API_KEY'
base_url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'

# Fonction pour rechercher des vulnérabilités dans la base de données NVD
def search_vulnerabilities(product, version):
    params = {
        'apiKey': api_key,
        'keyword': f'{product} {version}',
        'resultsPerPage': 10,
        'startIndex': 0
    }
    response = requests.get(base_url, params=params)
    
    if response.status_code == 200:
        data = response.json()
        return data.get('result', {}).get('CVE_Items', [])
    else:
        print(f'Erreur {response.status_code}: {response.text}')
        return []

# Fonction pour scanner les ports ouverts
def scan_open_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-p-')  # Scan all ports
    open_ports = {}
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            open_ports[host] = ports
    return open_ports, nm

# Fonction pour récupérer les CVE pour un service
def fetch_cves(service_name):
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service_name}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json().get('result', {}).get('CVE_Items', [])
    return []

# Fonction principale pour scanner et trouver les CVE
def find_cves_for_open_ports(target):
    open_ports, nm = scan_open_ports(target)
    cves = {}
    for host, ports in open_ports.items():
        for port in ports:
            service_name = nm[host]['tcp'][port]['name']
            cve_list = fetch_cves(service_name)
            cves[port] = cve_list
    return cves

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        target_ip = request.form.get('target_ip')
        if target_ip:
            cves = find_cves_for_open_ports(target_ip)
            return render_template('scan_results.html', cves=cves)
        else:
            error_message = "Veuillez spécifier une adresse IP cible."
            return render_template('error.html', error_message=error_message)
    return render_template('scan_form.html')


@app.route('/connexion')
def connexion():
    collection = db['users']
    result = collection.find()
    return render_template('index.html', data=result)


# Page d'inscription
@app.route('/register', methods=["POST", "GET"])
def register():
    user = None  
    error = None
    if request.method == "POST":
        db = connect_to_database()  
        nom = request.form['nom']
        prenom = request.form['prenom']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            error = "Les mots de passe ne correspondent pas."
            return render_template("register.html", error=error)

        hashed_password = generate_password_hash(password)

        user = db.users.find_one({'nom': nom})
        if user:
            error = "Nom d'utilisateur déjà pris, veuillez choisir un nom d'utilisateur différent."
            return render_template("register.html", error=error)

        db.users.insert_one({
            'nom': nom,
            'prenom': prenom,
            'email': email,
            'password': hashed_password
        })
        session['user'] = nom
        return redirect(url_for('login'))
    return render_template("register.html", user=user)

# Page de connexion
@app.route('/', methods=["POST", "GET"])
def login():
    user = None
    error = None
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password'] 
        
        # Utilisation directe de la connexion à la base de données MongoDB
        user = db.users.find_one({'email': email})
        
        if user:
            if check_password_hash(user['password'], password):
                session['user'] = user['nom']
                return redirect(url_for('acceil'))  
            else:
                error = "Le nom d'utilisateur ou le mot de passe ne correspondent pas. Veuillez réessayer."
        else:
            error = "Le nom d'utilisateur ou le mot de passe ne correspondent pas. Veuillez réessayer."
   
    return render_template("login.html", user=user, error=error)


# Page "home"
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

# Page "contact"
@app.route("/contact")
def contact():
    return render_template("contact.html")

def find_subdomains(domain):
    try:
        subdomains = sublist3r.main(domain, 40, 'sublist.txt', ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        return subdomains
    except Exception as e:
        print("Error:", str(e))
        return []

def read_results(domain):
    ips = []
    subdomains = []
    try:
        subdomains = find_subdomains(domain)
        ips = subprocess.check_output(['nslookup', domain]).decode().split('\n')
        ips = [line.split()[-1] for line in ips if 'Address' in line and '127.0.0.1' not in line]
    except subprocess.CalledProcessError as e:
        print("DNS resolution failed:", str(e))
    except Exception as e:
        print("Error:", str(e))
    return ips, subdomains



def collect_information(domain):
    # Vous pouvez implémenter ici la logique pour collecter des informations sur le domaine
     #Par exemple, vous pouvez util des API en ligne ou des outils locaux pour recueillir des informations
    pass


   
@app.route('/vulnerabilites', methods=['GET', 'POST'])
def vulnerabilities():
    if request.method == 'POST':
        domain = request.form.get('domain')
        if domain:
            # Lisez les résultats pour le domaine spécifié
            ips, subdomains = read_results(domain)
            # Filtrer les doublons dans la liste des sous-domaines
            unique_subdomains = list(set(subdomains))
            # Passez les résultats filtrés au template HTML
            return render_template('vulnerabilites.html', domain=domain, ips=ips, subdomains=unique_subdomains)
        else:
            error_message = "Veuillez spécifier un nom de domaine."
            return render_template('error.html', error_message=error_message)
    return render_template('Acceil.html')

#@app.route('/scan_ips', methods=['POST'])
#def scan_ips():
#    ips = request.form.getlist('ips')
#    results = {}

#    for ip in ips:
#        if ip:  # Vérifiez que l'IP n'est pas vide
#            nmap_command = f"sudo nmap -sV --script=vulscan/vulscan.nse {ip}"
#            try:
#                result = subprocess.check_output(nmap_command, shell=True).decode('utf-8')
#                results[ip] = result
#            except subprocess.CalledProcessError as e:
#                results[ip] = str(e)

#    return render_template('scan_results.html', results=results)

@app.route('/scan_ips', methods=['POST'])
def scan_ips():
    ips = request.form.getlist('ips')
    domain_name = request.form.get('domain_name')
    user_id = session.get('user_id')  # Supposez que l'ID utilisateur est stocké dans la session
    
    scan_id = str(uuid.uuid4())
    
    db.scans.insert_one({
        'scan_id': scan_id,  # Utilisez l'UUID généré pour scan_id
        'user_id': user_id,
        'domain_name': domain_name,
        'ips': ips,
        'open_ports': [],
        'results': [],
        'scan_date': datetime.datetime.now()
    })
    
    results = {}
    open_ports = []

    for ip in ips:
        if ip:  # Vérifiez que l'IP n'est pas vide
            nmap_command = f"sudo nmap -sV --script=vulscan/vulscan.nse {ip}"
            try:
                result = subprocess.check_output(nmap_command, shell=True).decode('utf-8')
                results[ip] = result
                result_id = str(uuid.uuid4())          
                # Stocker les résultats bruts dans la collection 'results'
                db.results.insert_one({
                    'result_id': result_id,
                    'scan_id': scan_id,
                    'scan_date': datetime.datetime.now(),
                    'ips': ips,
                    'domain_name': domain_name,
                    'result': result
                })
                
                # Extraire les ports ouverts et les vulnérabilités du résultat
                open_ports += extract_open_ports(result)
                vulnerabilities = extract_vulnerabilities(result)
                
                for vuln in vulnerabilities:
                    vuln_id = str(uuid.uuid4())
                    db.vulnerabilities.insert_one({
                        'vuln_id': vuln_id,
                        'scan_id': scan_id,
                        'ip': ip,
                        'vulnerability': vuln,
                        'timestamp': datetime.datetime.now()
                    })
                    
            except subprocess.CalledProcessError as e:
                results[ip] = str(e)
    
    db.scans.update_one({'_id': scan_id}, {'$set': {'open_ports': open_ports, 'results': list(results.keys())}})
    
    return render_template('scan_results.html', results=results)

def extract_open_ports(scan_result):
    # Dummy extraction logic for open ports, replace with actual parsing logic
    open_ports = []
    lines = scan_result.split('\n')
    for line in lines:
        if 'open' in line:  # This is a placeholder condition
            open_ports.append(line)
    return open_ports

def extract_vulnerabilities(scan_result):
    # Dummy extraction logic for vulnerabilities, replace with actual parsing logic
    vulnerabilities = []
    lines = scan_result.split('\n')
    for line in lines:
        if 'VULNERABILITY' in line:  # This is a placeholder condition
            vulnerabilities.append(line)
    return vulnerabilities

@app.route('/view_vulnerabilities')
def view_vulnerabilities():
    vulnerabilities = db.vulnerabilities.find()
    return render_template('view_vulnerabilities.html', vulnerabilities=vulnerabilities)

@app.route('/view_results')
def view_results():
    results = db.results.find()
    return render_template('view_results.html', results=results)


@app.route('/about')
def about():
    return render_template('about.html')

# Route pour afficher le formulaire de scan
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(port=5001, debug=True)
