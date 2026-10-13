from datetime import datetime, timedelta
from flask import Flask, request, render_template_string

app = Flask(__name__)

SEUIL = 3
FENETRE = timedelta(minutes=1)

PAGE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>mini-siem</title>
    <style>
        :root {
            --fond: #0d1117;
            --carte: rgba(22, 27, 34, 0.88);
            --bordure: #30363d;
            --texte: #e6edf3;
            --discret: #8b949e;
            --accent: #00e676;
            --rouge: #f85149;
            --vert: #3fb950;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            background: var(--fond);
            color: var(--texte);
            font-family: "Segoe UI", Arial, sans-serif;
            line-height: 1.5;
        }
        header {
            border-bottom: 1px solid var(--bordure);
            padding: 20px;
            text-align: center;
        }
        header h1 { margin: 0; font-size: 28px; }
        header h1 span { color: var(--accent); }
        header p { margin: 6px 0 0; color: var(--discret); }
        main { max-width: 800px; margin: 30px auto; padding: 0 20px; }
        .carte {
            background: var(--carte);
            border: 1px solid var(--bordure);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }
        .carte h2 { margin-top: 0; font-size: 18px; }
        textarea {
            width: 100%;
            height: 220px;
            background: var(--fond);
            color: var(--texte);
            border: 1px solid var(--bordure);
            border-radius: 8px;
            padding: 12px;
            font-family: Consolas, monospace;
            font-size: 14px;
            resize: vertical;
        }
        textarea:focus { outline: 2px solid var(--accent); }
        .boutons { display: flex; gap: 12px; margin-top: 16px; flex-wrap: wrap; }
        button {
            padding: 10px 22px;
            font-size: 15px;
            border-radius: 8px;
            cursor: pointer;
            border: 1px solid var(--bordure);
            color: var(--texte);
            background: var(--carte);
        }
        button.principal { background: var(--accent); border-color: var(--accent); font-weight: bold; color: #0d1117; }
        button:hover { opacity: 0.85; }
        .resultat {
            padding: 14px 16px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 5px solid;
        }
        .alerte { background: rgba(248, 81, 73, 0.12); border-color: var(--rouge); }
        .ok { background: rgba(63, 185, 80, 0.12); border-color: var(--vert); }
        footer { text-align: center; color: var(--discret); padding: 20px; font-size: 14px; }
        #matrix { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; opacity: 0.10; }
    </style>
</head>
<body>
    <canvas id="matrix"></canvas>

    <header>
        <h1>🛡️ mini-<span>siem</span></h1>
        <p>Détecte les attaques par force brute dans tes logs</p>
    </header>

    <main>
        <div class="carte">
            <h2>1. Colle tes logs</h2>
            <form method="post">
                <textarea id="logs" name="logs" placeholder="2026-10-05 10:15:01 Failed login for user admin from 192.168.1.50">{{ logs }}</textarea>
                <div class="boutons">
                    <button type="submit" class="principal">🔍 Analyser</button>
                    <button type="button" onclick="chargerExemple()">Charger un exemple</button>
                </div>
            </form>
        </div>

        {% if resultats is not none %}
        <div class="carte">
            <h2>2. Résultats</h2>
            {% if resultats|length == 0 %}
                <p>Aucune tentative de connexion échouée trouvée.</p>
            {% endif %}
            {% for r in resultats %}
                <div class="resultat {{ r.classe }}">
                    {% if r.classe == "alerte" %}🚨{% else %}✅{% endif %} {{ r.texte }}
                </div>
            {% endfor %}
        </div>
        {% endif %}
    </main>

    <footer>Projet mini-siem · fait avec Python et Flask</footer>

    <script>
        function chargerExemple() {
            document.getElementById("logs").value = `2026-10-05 10:15:01 Failed login for user admin from 192.168.1.50
2026-10-05 10:15:03 Failed login for user admin from 192.168.1.50
2026-10-05 10:15:05 Failed login for user admin from 192.168.1.50
2026-10-05 10:15:09 Failed login for user root from 10.0.0.8
2026-10-05 10:16:10 Successful login for user henri from 192.168.1.20
2026-10-05 10:17:02 Failed login for user root from 10.0.0.8
2026-10-05 10:17:06 Failed login for user test from 172.16.5.4`;
        }

        const canvas = document.getElementById("matrix");
        const ctx = canvas.getContext("2d");
        function taille() { canvas.width = innerWidth; canvas.height = innerHeight; }
        taille();
        addEventListener("resize", taille);

        const lettres = "01ABCDEF<>/#$%";
        const taillePolice = 16;
        let gouttes = [];

        function dessiner() {
            const colonnes = Math.floor(canvas.width / taillePolice);
            while (gouttes.length < colonnes) gouttes.push(Math.random() * -50);
            ctx.fillStyle = "rgba(13, 17, 23, 0.08)";
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = "#00e676";
            ctx.font = taillePolice + "px monospace";
            for (let i = 0; i < colonnes; i++) {
                const c = lettres[Math.floor(Math.random() * lettres.length)];
                ctx.fillText(c, i * taillePolice, gouttes[i] * taillePolice);
                if (gouttes[i] * taillePolice > canvas.height && Math.random() > 0.975) gouttes[i] = 0;
                gouttes[i]++;
            }
        }
        setInterval(dessiner, 50);
    </script>
</body>
</html>
"""


def analyser(texte):
    echecs = {}
    for ligne in texte.splitlines():
        if "Failed login" in ligne:
            mots = ligne.strip().split()
            try:
                heure = datetime.strptime(mots[0] + " " + mots[1], "%Y-%m-%d %H:%M:%S")
            except (ValueError, IndexError):
                continue  # ligne mal formée : on l'ignore
            ip = mots[-1]
            echecs.setdefault(ip, []).append(heure)

    resultats = []
    for ip, heures in echecs.items():
        for i in range(len(heures)):
            groupe = [h for h in heures if heures[i] <= h < heures[i] + FENETRE]
            if len(groupe) >= SEUIL:
                resultats.append({"classe": "alerte",
                                  "texte": f"ALERTE : {ip} - {len(groupe)} échecs en moins d'une minute"})
                break
        else:
            resultats.append({"classe": "ok",
                              "texte": f"OK : {ip} - {len(heures)} échec(s)"})
    return resultats


@app.route("/", methods=["GET", "POST"])
def accueil():
    logs = ""
    resultats = None
    if request.method == "POST":
        logs = request.form.get("logs", "")
        resultats = analyser(logs)
    return render_template_string(PAGE, logs=logs, resultats=resultats)


if __name__ == "__main__":
    app.run(debug=True)