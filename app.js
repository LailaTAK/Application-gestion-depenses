const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const connection = require('./db');  // Import de la connexion à la base de données
require('dotenv').config();  // Charger les variables d'environnement

const app = express();
const port = process.env.PORT || 3000;

// Middleware pour parser les données JSON
app.use(bodyParser.json());
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});
console.log('Essai de connexion à la base de données...');
connection.connect((err) => {
  if (err) {
    console.error('Erreur de connexion à la base de données:', err.message);
  } else {
    console.log('Connecté à la base de données MySQL.');
  }
});
// Route d'inscription
app.post('/register', (req, res) => {
    const { full_name, email, username, password, currency, budget } = req.body;

    // Vérifier si l'email est déjà pris
    connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error('Erreur SQL:', err);
            return res.status(500).json({ message: 'Erreur serveur' });
        }

        if (results.length > 0) {
            return res.status(400).json({ message: 'L\'email est déjà utilisé' });
        }

        // Hash du mot de passe
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error('Erreur lors du hashage du mot de passe:', err);
                return res.status(500).json({ message: 'Erreur serveur' });
            }

            // Insertion de l'utilisateur dans la base de données
            const query = 'INSERT INTO users (nom, email, nomUtilisateur, password, currency, budget) VALUES (?, ?, ?, ?, ?, ?)';
            connection.query(query, [full_name, email, username, hashedPassword, currency, budget], (err, results) => {
                if (err) {
                    console.error('Erreur SQL:', err);
                    return res.status(500).json({ message: 'Erreur serveur' });
                }

                res.status(201).json({ message: 'Utilisateur créé avec succès' });
            });
        });
    });
});

// Route de connexion
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Rechercher l'utilisateur dans la base de données
    connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error('Erreur SQL:', err);
            return res.status(500).json({ message: 'Erreur serveur' });
        }

        if (results.length === 0) {
            return res.status(400).json({ message: 'Utilisateur non trouvé' });
        }

        const user = results[0];

        // Comparer les mots de passe
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error('Erreur lors de la comparaison des mots de passe:', err);
                return res.status(500).json({ message: 'Erreur serveur' });
            }

            if (!isMatch) {
                return res.status(400).json({ message: 'Mot de passe incorrect' });
            }

            // Générer le JWT
            const token = jwt.sign({ id: user.id_utilisateur, email: user.email }, process.env.JWT_SECRET, {
                expiresIn: '1h',  // Le token expire après 1 heure
            });

            res.json({ message: 'Connexion réussie', token });
        });
    });
});

// Route pour tester la connexion (par exemple pour accéder à la page principale)
app.get('/profile', (req, res) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ message: 'Token manquant' });
    }

    // Vérification du token JWT
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Token invalide' });
        }

        // Si le token est valide, retourner les informations de l'utilisateur
        connection.query('SELECT * FROM users WHERE id_utilisateur = ?', [decoded.id], (err, results) => {
            if (err) {
                console.error('Erreur SQL:', err);
                return res.status(500).json({ message: 'Erreur serveur' });
            }

            if (results.length === 0) {
                return res.status(404).json({ message: 'Utilisateur non trouvé' });
            }

            res.json({ user: results[0] });
        });
    });
});



const cors = require('cors');
app.use(cors());


// Lancer le serveur
app.listen(port, () => {
  console.log(`Serveur en cours d'exécution sur le port ${port}`);
});