# Dockerfile pour le service Flask
FROM python:3.9-slim

WORKDIR /app

# Copier les dépendances
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

# Copier tout le projet
COPY . .

# Démarrer l'application Flask
CMD ["python", "appV2.py"]

# Exposer le port 5000
EXPOSE 5000
