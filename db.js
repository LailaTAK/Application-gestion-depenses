const mysql = require('mysql2');
require('dotenv').config();

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

connection.connect((err) => {
  if (err) {
    console.error('Erreur de connexion à la base de données:', err.message);
    // Ajout d'un message plus détaillé
    console.log('Vérifiez vos informations de connexion dans le fichier .env');
  } else {
    console.log('Connecté à la base de données MySQL.');
  }
});

module.exports = connection;