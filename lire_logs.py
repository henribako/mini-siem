from datetime import datetime, timedelta

SEUIL = 3                       # nombre d'échecs pour déclencher l'alerte
FENETRE = timedelta(minutes=1)  # dans cette durée

# On range, pour chaque IP, la liste des heures de ses échecs
echecs = {}

with open("test.log", "r", encoding="utf-8") as fichier:
    for ligne in fichier:
        if "Failed login" in ligne:
            mots = ligne.strip().split()
            heure = datetime.strptime(mots[0] + " " + mots[1], "%Y-%m-%d %H:%M:%S")
            ip = mots[-1]
            echecs.setdefault(ip, []).append(heure)

print("=== Rapport de sécurité ===")
for ip, heures in echecs.items():
    alerte = False
    for i in range(len(heures)):
        # combien d'échecs dans la minute qui suit cet échec ?
        groupe = [h for h in heures if heures[i] <= h < heures[i] + FENETRE]
        if len(groupe) >= SEUIL:
            alerte = True
            break
    if alerte:
        print("ALERTE :", ip, "-", SEUIL, "échecs ou plus en moins d'une minute")
    else:
        print("OK     :", ip, "-", len(heures), "échec(s), pas de rafale")