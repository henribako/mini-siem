# Compte les connexions ratées pour chaque adresse IP
echecs = {}

with open("test.log", "r", encoding="utf-8") as fichier:
    for ligne in fichier:
        if "Failed login" in ligne:
            ip = ligne.strip().split()[-1]
            echecs[ip] = echecs.get(ip, 0) + 1

for ip, nombre in echecs.items():
    print(ip, "a raté sa connexion", nombre, "fois")
    if nombre >= 3:
        print("ALERTE : activité suspecte depuis", ip)