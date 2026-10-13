from datetime import datetime, timedelta
from flask import Flask, request, render_template_string

app = Flask(__name__)

SEUIL_DEFAUT = 3      # nombre d'échecs
FENETRE_DEFAUT = 60   # en secondes

PAGE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>mini-siem</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
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
        textarea:focus, input:focus { outline: 2px solid var(--accent); }
        .reglages { display: flex; gap: 20px; margin-top: 16px; flex-wrap: wrap; }
        .reglages label { display: flex; flex-direction: column; font-size: 14px; color: var(--discret); gap: 6px; }
        input[type=number] {
            width: 160px;
            background: var(--fond);
            color: var(--texte);
            border: 1px solid var(--bordure);
            border-radius: 8px;
            padding: 10px;
            font-size: 15px;
        }
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
        .resume { color: var(--discret); margin-bottom: 12px; }
        .resultat {
            padding: 14px 16px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 5px solid;
        }
        .alerte { background: rgba(248, 81, 73, 0.12); border-color: var(--rouge); }
        .ok { background: rgba(63, 185, 80, 0.12); border-color: var(--vert); }
        footer { text-align: center; color: var(--discret); padding: 20px; font-size: 14px; }
        #matrix { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; opacity: 0.3; }
        .stats { display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
        .stat { flex: 1; min-width: 140px; background: var(--fond); border: 1px solid var(--bordure); border-radius: 10px; padding: 14px; text-align: center; }
        .stat b { display: block; font-size: 28px; color: var(--accent); }
        .stat.danger b { color: var(--rouge); }
        .stat span { color: var(--discret); font-size: 13px; }
        .graphique { background: var(--fond); border: 1px solid var(--bordure); border-radius: 10px; padding: 14px; margin-bottom: 16px; }
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

                <div class="reglages">
                    <label>
                        Seuil d'alerte (nombre d'échecs)
                        <input type="number" name="seuil" min="1" max="1000" value="{{ seuil }}">
                    </label>
                    <label>
                        Fenêtre de temps (secondes)
                        <input type="number" name="fenetre" min="1" max="86400" value="{{ fenetre }}">
                    </label>
                </div>

                <div class="boutons">
                    <button type="submit" class="principal">🔍 Analyser</button>
                    <button type="button" onclick="chargerExemple()">Charger un exemple</button>
                </div>
            </form>
        </div>

        {% if resultats is not none %}
        <div class="carte">
            <h2>2. Résultats</h2>
            <div class="resume">Règle utilisée : {{ seuil }} échecs ou plus en {{ fenetre }} secondes.</div>

            {% if resultats|length == 0 %}
                <p>Aucune tentative de connexion échouée trouvée.</p>
            {% else %}
                <div class="stats">
                    <div class="stat"><b>{{ resultats|length }}</b><span>IP analysées</span></div>
                    <div class="stat danger"><b>{{ nb_alertes }}</b><span>Alertes</span></div>
                    <div class="stat"><b>{{ total_echecs }}</b><span>Échecs au total</span></div>
                </div>

                <div class="graphique">
                    <canvas id="graph" height="120"></canvas>
                </div>
            {% endif %}

            {% for r in resultats %}
                <div class="resultat {{ r.classe }}">
                    {% if r.classe == "alerte" %}🚨{% else %}✅{% endif %} {{ r.texte }}
                </div>
            {% endfor %}
        </div>

        <script>
            const donnees = {{ resultats|tojson }};
            const zone = document.getElementById("graph");
            if (zone) {
                new Chart(zone, {
                    type: "bar",
                    data: {
                        labels: donnees.map(r => r.ip),
                        datasets: [{
                            label: "Échecs de connexion",
                            data: donnees.map(r => r.echecs),
                            backgroundColor: donnees.map(r => r.classe === "alerte" ? "#f85149" : "#3fb950")
                        }]
                    },
                    options: {
                        plugins: { legend: { labels: { color: "#e6edf3" } } },
                        scales: {
                            x: { ticks: { color: "#8b949e" }, grid: { color: "#30363d" } },
                            y: { beginAtZero: true, ticks: { color: "#8b949e", precision: 0 }, grid: { color: "#30363d" } }
                        }
                    }
                });
            }
        </script>
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


def lire_nombre(valeur, defaut, minimum, maximum):
    """Transforme le texte du formulaire en nombre, avec des limites de sécurité."""
    try:
        nombre = int(valeur)
    except (TypeError, ValueError):
        return defaut
    return max(minimum, min(maximum, nombre))


def analyser(texte, seuil, fenetre_secondes):
    fenetre = timedelta(seconds=fenetre_secondes)
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
            groupe = [h for h in heures if heures[i] <= h < heures[i] + fenetre]
            if len(groupe) >= seuil:
                resultats.append({"classe": "alerte", "ip": ip, "echecs": len(heures),
                                  "texte": f"ALERTE : {ip} - {len(groupe)} échecs en moins de {fenetre_secondes} s"})
                break
        else:
            resultats.append({"classe": "ok", "ip": ip, "echecs": len(heures),
                              "texte": f"OK : {ip} - {len(heures)} échec(s) au total, pas de rafale"})
    return resultats


@app.route("/", methods=["GET", "POST"])
def accueil():
    logs = ""
    resultats = None
    seuil = SEUIL_DEFAUT
    fenetre = FENETRE_DEFAUT
    nb_alertes = 0
    total_echecs = 0
    if request.method == "POST":
        logs = request.form.get("logs", "")
        seuil = lire_nombre(request.form.get("seuil"), SEUIL_DEFAUT, 1, 1000)
        fenetre = lire_nombre(request.form.get("fenetre"), FENETRE_DEFAUT, 1, 86400)
        resultats = analyser(logs, seuil, fenetre)
        nb_alertes = sum(1 for r in resultats if r["classe"] == "alerte")
        total_echecs = sum(r["echecs"] for r in resultats)
    return render_template_string(PAGE, logs=logs, resultats=resultats,
                                  seuil=seuil, fenetre=fenetre,
                                  nb_alertes=nb_alertes, total_echecs=total_echecs)


if __name__ == "__main__":
    app.run(debug=True)