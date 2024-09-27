import os
import datetime
import uuid
import re
import subprocess
from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import concurrent.futures

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = os.urandom(24)

# Fonction de connexion à la base de données MongoDB
def connect_to_database():
    client = MongoClient('mongodb://localhost:27017/')  # Connexion locale par défaut
    return client['SecurityScanDB']  # Remplacez par le nom de votre base de données

# Connexion à la base de données MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['SecurityScanDB']

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
        command = f"theharvester -d {domain} -b all -f resultats.txt"
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Error:", str(e))


def read_results():
    ips = []
    subdomains = []
    try:
        with open('resultats.txt', 'r') as file:
            content = file.read()
            # Utiliser les expressions régulières pour extraire les adresses IP et les sous-domaines
            ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", content)
            # Filtrer les sous-domaines pour exclure search.brave.com
            subdomains = re.findall(r"(?:http|https)://([\w\.-]+)", content)
            subdomains = [subdomain for subdomain in subdomains if subdomain != "search.brave.com"]
    except FileNotFoundError:
        print("Le fichier resultats.txt n'a pas été trouvé.")
    return ips, subdomains


def collect_information(domain):
    try:
        command = f"theharvester -d {domain} -b all -f resultats.txt"
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Error:", str(e))

    # Lire les résultats du fichier resultats.txt
    ips, subdomains = read_results()

    return ips, subdomains


def extract_vulnerabilities(scan_result):
    vulnerabilities = []
    lines = scan_result.split('\n')
    for line in lines:
        if 'VULNERABILITY' in line:  # This is a placeholder condition
            vulnerabilities.append(line)
    return vulnerabilities

def extract_open_ports(scan_result):
    open_ports = []
    lines = scan_result.split('\n')
    for line in lines:
        if '/tcp' in line and 'open' in line:
            port = line.split('/')[0]
            open_ports.append(port)
    return open_ports

def scan_ip(ip, scan_id, domain_name):
    nmap_command = f"sudo nmap -sV --script=vulscan/vulscan.nse {ip}"
    try:
        result = subprocess.check_output(nmap_command, shell=True).decode('utf-8')
        result_id = str(uuid.uuid4())          
        # Stocker les résultats bruts dans la collection 'results'
        db.results.insert_one({
            'result_id': result_id,
            'scan_id': scan_id,
            'scan_date': datetime.datetime.now(),
            'ips': [ip],
            'domain_name': domain_name,
            'result': result
        })
        
        # Extraire les ports ouverts et les vulnérabilités du résultat
        open_ports = extract_open_ports(result)
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
        return (ip, result, open_ports)
    except subprocess.CalledProcessError as e:
        return (ip, str(e), [])

@app.route('/scan_ips', methods=['POST'])
def scan_ips():
    ips = request.form.getlist('ips')
    domain_name = request.form.get('domain_name')
    user_id = session.get('user')  # Suppose que l'utilisateur est stocké dans la session
    
    scan_id = str(uuid.uuid4())
    
    db.scans.insert_one({
        'scan_id': scan_id,
        'user_id': user_id,
        'domain_name': domain_name,
        'ips': ips,
        'open_ports': [],
        'results': [],
        'scan_date': datetime.datetime.now()
    })
    
    results = {}
    open_ports = []

    # Utiliser ThreadPoolExecutor pour scanner les IPs en parallèle
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_ip = {executor.submit(scan_ip, ip, scan_id, domain_name): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                ip, result, ports = future.result()
                results[ip] = result
                open_ports.extend(ports)
            except Exception as e:
                results[ip] = str(e)
    
    db.scans.update_one({'scan_id': scan_id}, {'$set': {'open_ports': open_ports, 'results': list(results.keys())}})
    
    return render_template('scan_results.html', results=results, scan_id=scan_id)

@app.route('/vulnerabilities', methods=['GET', 'POST'])
def vulnerabilities():
    if request.method == 'POST':
        domain = request.form.get('domain')
        if domain:
            # Collecter des informations sur le domaine en utilisant The Harvester
            ips, subdomains = collect_information(domain)
            unique_subdomains = list(set(subdomains))
            # Passer les résultats au template HTML
            return render_template('vulnerabilites.html', domain=domain, ips=ips, subdomains=unique_subdomains)
        else:
            error_message = "Veuillez spécifier un nom de domaine."
            return render_template('error.html', error_message=error_message)
    return render_template('Acceil.html')



def get_application_details(ip, port):
    # Code pour récupérer les détails de l'application pour l'adresse IP et le port donnés
    # Vous pouvez implémenter cette fonction en fonction de vos besoins
    # Par exemple, vous pouvez interroger une base de données ou utiliser une API pour récupérer les détails de l'application
    # Pour l'instant, je vais simplement renvoyer un dictionnaire vide
    
    return {}



@app.route('/application_details', methods=['GET'])
def application_details():
    ip = request.args.get('ip')
    port = request.args.get('port')
    domain = request.args.get('domain')  # Ajout du paramètre de domaine
    subdomains = request.args.getlist('subdomains')  # Ajout du paramètre de sous-domaines
    
    application_details = get_application_details(ip, port)
    
    return render_template('application_details.html', ip=ip, port=port, domain=domain, subdomains=subdomains, details=application_details)


@app.route('/about')
def about():
    return render_template('about.html')
# Route pour afficher le formulaire de scan
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(port=5001, debug=True)
