"""Récupère chaque jour les données Linky (Conso API, conso.boris.sh) et les enregistre chiffrées
dans docs/donnees.chiffre (lisibles uniquement avec le mot de passe de la page)."""
import base64, datetime as dt, json, os, re, sys, time, urllib.error, urllib.parse, urllib.request
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

TZ = ZoneInfo("Europe/Paris")
API = "https://conso.boris.sh/api/"
ICI = os.path.dirname(os.path.abspath(__file__))
FICHIER = os.path.join(ICI, "docs", "donnees.chiffre")
ITERATIONS = 310_000
JOURS_COURBE_GARDES = 62


# ---------- chiffrement (compatible avec la page web) ----------
def cle(mdp, sel):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sel, iterations=ITERATIONS).derive(mdp.encode())

def chiffrer(obj, mdp):
    sel, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(cle(mdp, sel)).encrypt(iv, json.dumps(obj, separators=(",", ":")).encode(), None)
    b = lambda x: base64.b64encode(x).decode()
    return json.dumps({"v": 1, "iter": ITERATIONS, "sel": b(sel), "iv": b(iv), "donnees": b(ct)})

def dechiffrer(txt, mdp):
    e = json.loads(txt)
    d = lambda k: base64.b64decode(e[k])
    return json.loads(AESGCM(cle(mdp, d("sel"))).decrypt(d("iv"), d("donnees"), None))


# ---------- lecture des réponses, quel que soit le format Enedis ----------
def extraire_points(racine):
    res = []
    def choisir(o, cles):
        for k in cles:
            if o.get(k) is not None:
                return o[k]
    def parcourir(o, unite, pas):
        if isinstance(o, list):
            for x in o:
                parcourir(x, unite, pas)
            return
        if not isinstance(o, dict):
            return
        rt = o.get("reading_type") if isinstance(o.get("reading_type"), dict) else {}
        u = choisir(o, ["unite", "unit", "uniteMesure"])
        unite = u if isinstance(u, str) else rt.get("unit", unite)
        p = choisir(o, ["pas", "interval_length", "p", "mesuresPas"])
        pas = p if isinstance(p, str) and p.startswith("P") else rt.get("interval_length", pas)
        v, d = choisir(o, ["v", "value", "valeur"]), choisir(o, ["d", "date", "horodatage", "dateMesure", "dateHeure"])
        if v is not None and isinstance(d, str) and re.match(r"^\d{4}-\d{2}-\d{2}", d):
            try:
                res.append({"d": d, "v": float(v), "unite": unite or "", "pas": pas or ""})
                return
            except (TypeError, ValueError):
                pass
        for val in o.values():
            if isinstance(val, (dict, list)):
                parcourir(val, unite, pas)
    parcourir(racine, None, None)
    return res

def lire_date(s):
    s = s.strip().replace("T", " ")
    if re.search(r"(Z|[+-]\d{2}:?\d{2})$", s) and len(s) > 10:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T")).astimezone(TZ)
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})(?: (\d{2}):(\d{2})(?::(\d{2}))?)?", s)
    return dt.datetime(*[int(x or 0) for x in m.groups()], tzinfo=TZ)

def pas_minutes(p):
    m = re.search(r"PT(?:(\d+)H)?(?:(\d+)M)?", p or "")
    tot = (int(m.group(1) or 0) * 60 + int(m.group(2) or 0)) if m else 0
    return tot or 30

def plages(txt):
    res = []
    for m in re.finditer(r"(\d{1,2})\s*[h:]?\s*(\d{2})?\s*(?:-|à)\s*(\d{1,2})\s*[h:]?\s*(\d{2})?", txt or "", re.I):
        res.append((int(m[1]) * 60 + int(m[2] or 0), int(m[3]) * 60 + int(m[4] or 0)))
    return res or [(22 * 60, 6 * 60)]

def est_hc(d, pl):
    t = d.hour * 60 + d.minute
    return any((a <= t < b) if a < b else (t >= a or t < b) for a, b in pl)


# ---------- appels API ----------
def appel(typ, prm, jeton, debut, fin):
    url = API + typ + "?" + urllib.parse.urlencode({"pointId": prm, "dateDebut": debut.isoformat(), "dateFin": fin.isoformat()})
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + jeton,
                                               "User-Agent": "suivi-conso (GitHub Actions, usage personnel)"})
    for essai in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                time.sleep(1)
                return extraire_points(json.load(r))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return []
            if e.code == 401:
                sys.exit("Jeton refusé (401) : refaites le consentement sur conso.boris.sh et mettez à jour le secret LINKY_JETON.")
            if e.code >= 500 and essai < 2:
                time.sleep(30)
                continue
            raise RuntimeError(f"{typ} : erreur {e.code} {e.read()[:200]!r}")

def blocs(debut, fin, taille):
    d = debut
    while d < fin:
        f = min(d + dt.timedelta(days=taille), fin)
        yield d, f
        d = f


# ---------- météo (Open-Meteo, gratuit, sans clé) ----------
def lire_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "suivi-conso (GitHub Actions, usage personnel)"})
    for essai in range(5):  # Open-Meteo répond parfois lentement : on insiste un peu
        try:
            with urllib.request.urlopen(req, timeout=40) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code < 500 or essai == 4:
                raise
        except Exception:
            if essai == 4:
                raise
        time.sleep(20 * (essai + 1))

def localiser(ville):
    """Code postal ou nom de commune -> (latitude, longitude), en France en priorité."""
    for pays in ("&countryCode=FR", ""):
        r = lire_json("https://geocoding-api.open-meteo.com/v1/search?count=1&language=fr&format=json&name="
                      + urllib.parse.quote(ville) + pays)
        if r.get("results"):
            return r["results"][0]["latitude"], r["results"][0]["longitude"]
    raise RuntimeError("ville introuvable")

def temperatures(lat, lon, debut, fin):
    """Température moyenne de chaque jour de debut à fin (inclus), en °C."""
    res = {}
    def lire(r):
        dl = r.get("daily") or {}
        for j, t in zip(dl.get("time") or [], dl.get("temperature_2m_mean") or []):
            if t is not None:
                res[j] = round(float(t), 1)
    commun = f"latitude={lat}&longitude={lon}&daily=temperature_2m_mean&timezone=Europe%2FParis"
    if debut <= fin - dt.timedelta(days=5):  # archives (quelques jours de retard)
        lire(lire_json(f"https://archive-api.open-meteo.com/v1/archive?{commun}"
                       f"&start_date={debut.isoformat()}&end_date={(fin - dt.timedelta(days=2)).isoformat()}"))
    recents = {}
    r = lire_json(f"https://api.open-meteo.com/v1/forecast?{commun}&past_days=14&forecast_days=1")
    for j, t in zip(r["daily"]["time"], r["daily"]["temperature_2m_mean"]):
        if t is not None and debut.isoformat() <= j <= fin.isoformat():
            recents[j] = round(float(t), 1)
    for j, t in recents.items():
        res.setdefault(j, t)  # les archives priment, les prévisions récentes complètent
    return res


def main():
    prm = re.sub(r"\D", "", os.environ.get("LINKY_PRM", ""))
    jeton = os.environ.get("LINKY_JETON", "").strip()
    mdp = os.environ.get("MOT_DE_PASSE_PAGE", "")
    if len(prm) != 14 or not jeton or not mdp:
        sys.exit("Secrets manquants : LINKY_PRM (14 chiffres), LINKY_JETON et MOT_DE_PASSE_PAGE sont nécessaires.")
    cfg = json.load(open(os.path.join(ICI, "config.json"), encoding="utf-8"))
    pl = plages(cfg.get("heures_creuses"))

    donnees = {"jours": {}, "courbe": {}}
    if os.path.exists(FICHIER):
        try:
            donnees = dechiffrer(open(FICHIER).read(), mdp)
        except Exception:
            print("Données existantes illisibles (mot de passe changé ?) : on repart de zéro.")

    aujourdhui = dt.datetime.now(TZ).date()
    if donnees["jours"]:
        debut = dt.date.fromisoformat(max(donnees["jours"])) + dt.timedelta(days=1)
    else:
        debut = aujourdhui - dt.timedelta(days=int(cfg.get("jours_historique_premier_lancement", 365)))
    # on reprend toujours les 3 derniers jours au cas où Enedis aurait publié en retard
    debut = min(debut, aujourdhui - dt.timedelta(days=3))
    erreurs = []

    for a, b in blocs(debut, aujourdhui, 31):
        for p in appel("consommation_quotidienne", prm, jeton, a, b):
            wh = p["v"] * 1000 if p["unite"].lower() == "kwh" else p["v"]
            j = donnees["jours"].setdefault(lire_date(p["d"]).date().isoformat(), {})
            j["total"] = round(wh / 1000, 3)

    try:
        for a, b in blocs(debut, aujourdhui, 7):
            for p in appel("courbe_de_charge_consommation", prm, jeton, a, b):
                pm = pas_minutes(p["pas"])
                deb = lire_date(p["d"]) - dt.timedelta(minutes=pm)  # l'heure Enedis marque la fin du créneau
                u = p["unite"].lower()
                if "wh" in u:
                    kwh = p["v"] if u == "kwh" else p["v"] / 1000
                else:
                    kwh = (p["v"] * 1000 if u == "kw" else p["v"]) * pm / 60 / 1000
                donnees["courbe"][deb.strftime("%Y-%m-%dT%H:%M")] = [round(kwh, 4), "HC" if est_hc(deb, pl) else "HP"]
    except RuntimeError as e:
        erreurs.append(f"Courbe horaire indisponible ({e}). Activez la collecte horaire dans votre espace Enedis.")

    # reclasse toute la courbe gardée avec les plages actuelles (si elles ont changé dans config.json)
    for k, val in donnees["courbe"].items():
        val[1] = "HC" if est_hc(dt.datetime.fromisoformat(k), pl) else "HP"

    # heures pleines / creuses par jour, à partir de la courbe
    parjour = {}
    for k, (kwh, per) in donnees["courbe"].items():
        x = parjour.setdefault(k[:10], {"hp": 0.0, "hc": 0.0})
        x["hp" if per == "HP" else "hc"] += kwh
    for jour, x in parjour.items():
        j = donnees["jours"].setdefault(jour, {})
        j["hp"], j["hc"] = round(x["hp"], 3), round(x["hc"], 3)
        j.setdefault("total", round(x["hp"] + x["hc"], 3))

    # température extérieure du jour (secret VILLE : code postal ou nom de la commune)
    ville = os.environ.get("VILLE", "").strip()
    if ville:
        try:
            lat, lon = localiser(ville)
            sans_temp = [k for k in donnees["jours"] if "temp" not in donnees["jours"][k]]
            hier = aujourdhui - dt.timedelta(days=1)
            deb_meteo = min([dt.date.fromisoformat(k) for k in sans_temp] + [aujourdhui - dt.timedelta(days=10)])
            for jour, t in temperatures(lat, lon, deb_meteo, hier).items():
                if jour in donnees["jours"]:
                    donnees["jours"][jour]["temp"] = t
        except Exception as e:
            print(f"Météo : échec ({type(e).__name__} : {str(e)[:120]})")
        manque = [k for k in sorted(donnees["jours"])[-7:] if "temp" not in donnees["jours"][k]]
        if manque:
            erreurs.append("Température pas encore disponible pour : " + ", ".join(
                dt.date.fromisoformat(k).strftime("%d/%m") for k in manque) + ". Elle sera récupérée à la prochaine mise à jour.")
        print(f"Météo : {sum('temp' in v for v in donnees['jours'].values())} jours avec température sur {len(donnees['jours'])}.")
    else:
        erreurs.append("Pour afficher la température, ajoutez le secret VILLE (votre code postal) dans GitHub.")

    limite = (aujourdhui - dt.timedelta(days=JOURS_COURBE_GARDES)).isoformat()
    donnees["courbe"] = {k: v for k, v in sorted(donnees["courbe"].items()) if k >= limite}
    donnees["jours"] = {k: donnees["jours"][k] for k in sorted(donnees["jours"]) if "total" in donnees["jours"][k]}
    donnees["config"] = cfg
    donnees["mise_a_jour"] = dt.datetime.now(TZ).strftime("%d/%m/%Y %H:%M")
    donnees["erreurs"] = erreurs

    open(FICHIER, "w").write(chiffrer(donnees, mdp))
    print(f"OK : {len(donnees['jours'])} jours, {len(donnees['courbe'])} points horaires. {' '.join(erreurs)}")


if __name__ == "__main__":
    main()
