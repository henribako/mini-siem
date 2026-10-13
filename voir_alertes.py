import sqlite3

connexion = sqlite3.connect("siem.db")
curseur = connexion.cursor()

for ligne in curseur.execute("SELECT * FROM alertes"):
    print(ligne)

connexion.close()