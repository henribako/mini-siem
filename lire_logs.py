# Compte les connexions ratées pour chaque adresse IP
SEUIL = 3  # nombre d'échecs à partir duquel on déclenche une alerte

echecs = {}

with open("test.log", "r", encoding="utf-8") as fichier:
    for ligne in fichier:
        if "Failed login" in ligne:
            ip = ligne.strip().split()[-1]
            echecs[ip] = echecs.get(ip, 0) + 1

print("=== Rapport de sécurité ===")
for ip, nombre in echecs.items():
    if nombre >= SEUIL:
        print("ALERTE :", ip, "-", nombre, "échecs de connexion")
    else:
        print("OK     :", ip, "-", nombre, "échec(s)")