# Utiliser une image de base Node.js
FROM node:14

# Définir le répertoire de travail à l'intérieur du conteneur
WORKDIR /app

# Copier les fichiers de package pour installer les dépendances
COPY package.json package-lock.json ./

# Installer les dépendances Node.js
RUN npm install

# Copier tous les fichiers de l'application
COPY . .

# Exposer le port 3000 pour l'application Node.js
EXPOSE 3000

# Commande pour démarrer l'application
CMD ["npm", "start"]

