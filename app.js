const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("./model/user"); // Assurez-vous que le modèle est bien défini

const app = express();
const PORT = 3000;
const SECRET_KEY = "votre_secret_key";

// Connexion à MongoDB
mongoose.connect("mongodb://localhost:27017/auth_demo", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log("MongoDB connecté")).catch((err) => console.error(err));

// Middleware
app.use(bodyParser.json());
app.use(cors({
    origin: "http://localhost:4200",
    credentials: true,
}));

// =====================
// Routes d'authentification
// =====================

// Inscription
app.post("/api/register", async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: "Utilisateur enregistré avec succès" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erreur lors de l'inscription" });
    }
});

// Connexion
app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: "Identifiant ou mot de passe incorrect" });
        }

        const token = jwt.sign({ userId: user._id }, SECRET_KEY, { expiresIn: "5h" });
        res.status(200).json({ message: "Connexion réussie", token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erreur lors de la connexion" });
    }
});

// Accès à une route protégée
app.get("/api/secret", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: "Token manquant" });
    }

    const token = authHeader.split(" ")[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: "Token invalide ou expiré" });
        }
        res.status(200).json({ message: "Bienvenue sur la page protégée", userId: decoded.userId });
    });
});

// =====================
// Lancement du serveur
// =====================
app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`));
