import sqlite3
from datetime import datetime, timedelta

SEUIL = 3
FENETRE = timedelta(minutes=1)

# 1. Ouvre (ou crée) la base de données
connexion = sqlite3.connect("siem.db")
curseur = connexion.cursor()

# 2. Crée le tableau "alertes" s'il n'existe pas encore
curseur.execute("""
    CREATE TABLE IF NOT EXISTS alertes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT,
        ip TEXT,
        nombre_echecs INTEGER,
        type TEXT
    )
""")

# 3. Lit les logs (comme avant)
echecs = {}
with open("test.log", "r", encoding="utf-8") as fichier:
    for ligne in fichier:
        if "Failed login" in ligne:
            mots = ligne.strip().split()
            heure = datetime.strptime(mots[0] + " " + mots[1], "%Y-%m-%d %H:%M:%S")
            ip = mots[-1]
            echecs.setdefault(ip, []).append(heure)

# 4. Détecte et enregistre les alertes
print("=== Rapport de sécurité ===")
for ip, heures in echecs.items():
    for i in range(len(heures)):
        groupe = [h for h in heures if heures[i] <= h < heures[i] + FENETRE]
        if len(groupe) >= SEUIL:
            print("ALERTE :", ip, "-", len(groupe), "échecs en moins d'une minute")
            curseur.execute(
                "INSERT INTO alertes (date, ip, nombre_echecs, type) VALUES (?, ?, ?, ?)",
                (str(heures[i]), ip, len(groupe), "force brute"),
            )
            break
    else:
        print("OK     :", ip, "-", len(heures), "échec(s)")

# 5. Sauvegarde et ferme
connexion.commit()
connexion.close()