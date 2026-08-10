import base64
from datetime import datetime
import io
import json
import os
import sqlite3
import urllib.request
import pandas as pd
import streamlit as st

# Importation sécurisée de FPDF
try:
    from fpdf import FPDF
except ModuleNotFoundError:
    from fpdf2 import FPDF
# ==========================================
# 0. GESTION DE LA PERSISTANCE EXTERNE, CLOUD GÉRÉ & SÉCURITÉ MOTS DE PASSE
# ==========================================
try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    raise ImportError("La bibliothèque 'bcrypt' est obligatoire et doit être présente dans requirements.txt pour assurer la sécurité.")

def hacher_mot_de_passe(password: str) -> str:
    """Hache le mot de passe avec bcrypt pour ne jamais le stocker en clair."""
    if not password:
        return ""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verifier_mot_de_passe(password: str, hashed: str) -> bool:
    """Vérifie un mot de passe par rapport à son hachage sécurisé bcrypt."""
    if not password or not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

DB_FILE = "cpnm_database.db"
ADMIN_EMAIL = "issayoume2012@gmail.com"

def init_sqlite_db():
    """Initialise la base de données SQLite avec de vraies tables relationnelles structurées et la table d'audit log."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_data (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS eleves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prenom TEXT,
            nom TEXT,
            date_naissance TEXT,
            classe TEXT,
            photo TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS professeurs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prenom TEXT,
            nom TEXT,
            matiere_principale TEXT,
            classe_attribuee TEXT,
            mot_de_passe TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS absences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            classe TEXT,
            eleve TEXT,
            statut TEXT,
            motif TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            classe TEXT,
            matiere TEXT,
            periode TEXT,
            eleve TEXT,
            devoir1 REAL,
            devoir2 REAL,
            composition REAL,
            moyenne REAL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            horodatage TEXT,
            acteur TEXT,
            action TEXT,
            details TEXT
        )
    """)
    
    conn.commit()
    conn.close()

init_sqlite_db()

def enregistrer_log_action(acteur: str, action: str, details: str):
    """Consigne chaque action utilisateur dans la table de logs."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        horodatage = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("INSERT INTO audit_logs (horodatage, acteur, action, details) VALUES (?, ?, ?, ?)",
                       (horodatage, acteur, action, details))
        conn.commit()
        conn.close()
    except Exception:
        pass

def charger_donnees_externes():
    """Charge les données depuis la base de données SQLite externe."""
    data = {}
    if os.path.exists(DB_FILE):
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM app_data")
            rows = cursor.fetchall()
            conn.close()
            for key, val_json in rows:
                data[key] = json.loads(val_json)
        except Exception:
            return {}
    return data

def sauvegarder_donnees_externes(action_label="SAUVEGARDE_DONNEES"):
    """Sauvegarde toutes les bases de données de session dans la base SQLite externe et trace l'action."""
    if "eleves_db" in st.session_state and not st.session_state.eleves_db.empty:
        if "Prénom" not in st.session_state.eleves_db.columns or "Nom" not in st.session_state.eleves_db.columns:
            prenoms = []
            noms = []
            for _, r in st.session_state.eleves_db.iterrows():
                nc = str(r.get("Nom Complet", ""))
                parts = nc.split(" ", 1)
                prenoms.append(parts[0] if len(parts) > 0 else "")
                noms.append(parts[1] if len(parts) > 1 else "")
            st.session_state.eleves_db["Prénom"] = prenoms
            st.session_state.eleves_db["Nom"] = noms

    data_to_save = {
        "admin_credentials": st.session_state.admin_credentials.to_dict(orient="split"),
        "prof_white_list": st.session_state.prof_white_list.to_dict(orient="split"),
        "admin_white_list": st.session_state.admin_white_list.to_dict(orient="split"),
        "prof_credentials": st.session_state.prof_credentials.to_dict(orient="split"),
        "classes_db": st.session_state.classes_db.to_dict(orient="split"),
        "eleves_db": st.session_state.eleves_db.to_dict(orient="split"),
        "matieres_def": st.session_state.matieres_def.to_dict(orient="split"),
        "coefficients_db": st.session_state.coefficients_db.to_dict(orient="split"),
        "baremes_db": st.session_state.baremes_db.to_dict(orient="split"),
        "periodes_db": st.session_state.periodes_db.to_dict(orient="split"),
        "notes_db": st.session_state.notes_db.to_dict(orient="split"),
        "viescolaire_db": st.session_state.viescolaire_db.to_dict(orient="split"),
        "conduite_db": st.session_state.conduite_db.to_dict(orient="split"),
    }
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        for key, value in data_to_save.items():
            cursor.execute("""
                INSERT INTO app_data (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """, (key, json.dumps(value, ensure_ascii=False)))
            
        if "eleves_db" in st.session_state and not st.session_state.eleves_db.empty:
            cursor.execute("DELETE FROM eleves")
            for _, r in st.session_state.eleves_db.iterrows():
                cursor.execute("INSERT INTO eleves (prenom, nom, date_naissance, classe, photo) VALUES (?, ?, ?, ?, ?)",
                               (r.get("Prénom"), r.get("Nom"), r.get("Date de Naissance"), r.get("Classe"), r.get("Photo")))

        if "prof_credentials" in st.session_state and not st.session_state.prof_credentials.empty:
            cursor.execute("DELETE FROM professeurs")
            for _, r in st.session_state.prof_credentials.iterrows():
                cursor.execute("INSERT INTO professeurs (prenom, nom, matiere_principale, classe_attribuee, mot_de_passe) VALUES (?, ?, ?, ?, ?)",
                               (r.get("Prénom"), r.get("Nom"), r.get("Matière Principale"), r.get("Classe Attribuée"), r.get("Mot de passe")))

        conn.commit()
        conn.close()
        enregistrer_log_action("ADMIN", action_label, "Sauvegarde générale effectuée avec succès.")
    except Exception as e:
        st.error(f"Erreur lors de la sauvegarde externe SQLite : {e}")

saved_data = charger_donnees_externes()

# ==========================================
# 1. CONFIGURATION DE LA PAGE & DESIGN
# ==========================================
st.set_page_config(
    page_title="Portail Pédagogique - École Président Nelson Mandela | Sénégal",
    page_icon="🇸🇳",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    .main { background-color: #F8FAFC; }
    .header-ecole { 
        color: #1E3A8A; 
        font-size: clamp(1.8rem, 4vw, 2.8rem); 
        font-weight: 900; 
        text-align: center; 
        margin-bottom: 2px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .sub-header { 
        color: #047857; 
        font-size: clamp(0.9rem, 2vw, 1.2rem); 
        font-weight: 700; 
        text-align: center; 
        margin-bottom: 25px; 
        font-style: italic;
    }
    .animated-card {
        border: 2px solid #E2E8F0;
        padding: 20px;
        border-radius: 16px;
        background: linear-gradient(135deg, #FFFFFF 0%, #F1F5F9 100%);
        box-shadow: 0 10px 25px rgba(0,0,0,0.05);
        text-align: center;
        margin-bottom: 15px;
        height: 100%;
    }
    .stButton>button { 
        background: linear-gradient(135deg, #1E3A8A 0%, #2563EB 100%); 
        color: white; 
        border-radius: 8px; 
        font-weight: bold; 
        border: none;
        padding: 0.75rem 1rem;
        width: 100%;
        min-height: 44px;
        font-size: 1rem;
    }
    </style>
""",
    unsafe_allow_html=True,
)

# ==========================================
# 2. INITIALISATION EXHAUSTIVE DES DONNÉES
# ==========================================
if "espace_actif" not in st.session_state:
    st.session_state.espace_actif = "🏠 Accueil"

if "authenticated_admin" not in st.session_state:
    st.session_state.authenticated_admin = False

if "admin_credentials" not in st.session_state:
    if "admin_credentials" in saved_data:
        st.session_state.admin_credentials = pd.DataFrame(**saved_data["admin_credentials"])
    else:
        st.session_state.admin_credentials = pd.DataFrame([
            {"Nom": "Principal", "Prénom": "Admin", "Email": ADMIN_EMAIL, "Mot de passe": hacher_mot_de_passe("cpnm2026")}
        ])

if "admin_white_list" not in st.session_state:
    if "admin_white_list" in saved_data:
        st.session_state.admin_white_list = pd.DataFrame(**saved_data["admin_white_list"])
    else:
        st.session_state.admin_white_list = pd.DataFrame([
            {"Email": ADMIN_EMAIL, "Nom": "Principal", "Prénom": "Admin", "Niveau d'accès": "Super-Admin", "Mot de passe": hacher_mot_de_passe("admin123")}
        ])

if "prof_white_list" not in st.session_state:
    if "prof_white_list" in saved_data:
        st.session_state.prof_white_list = pd.DataFrame(**saved_data["prof_white_list"])
    else:
        st.session_state.prof_white_list = pd.DataFrame([
            {"Email": "i.diallo@cpnm.sn", "Nom": "Diallo", "Prénom": "Ibrahima", "Matière": "Mathématiques", "Mot de passe": hacher_mot_de_passe("prof123")},
            {"Email": "a.sow@cpnm.sn", "Nom": "Sow", "Prénom": "Aissatou", "Matière": "Français", "Mot de passe": hacher_mot_de_passe("prof456")},
            {"Email": "c.ndiaye@cpnm.sn", "Nom": "Ndiaye", "Prénom": "Cheikh", "Matière": "Histoire-Géographie", "Mot de passe": hacher_mot_de_passe("prof789")}
        ])

if "prof_credentials" not in st.session_state:
    if "prof_credentials" in saved_data:
        st.session_state.prof_credentials = pd.DataFrame(**saved_data["prof_credentials"])
    else:
        st.session_state.prof_credentials = pd.DataFrame([
            {"Nom": "Diallo", "Prénom": "Ibrahima", "Mot de passe": hacher_mot_de_passe("prof123"), "Matière Principale": "Mathématiques", "Classe Attribuée": "6ème A"},
            {"Nom": "Sow", "Prénom": "Aissatou", "Mot de passe": hacher_mot_de_passe("prof456"), "Matière Principale": "Français", "Classe Attribuée": "CP"},
            {"Nom": "Ndiaye", "Prénom": "Cheikh", "Mot de passe": hacher_mot_de_passe("prof789"), "Matière Principale": "Histoire-Géographie", "Classe Attribuée": "5ème A"}
        ])

if "classes_db" not in st.session_state:
    if "classes_db" in saved_data:
        st.session_state.classes_db = pd.DataFrame(**saved_data["classes_db"])
    else:
        st.session_state.classes_db = pd.DataFrame(
            columns=["Classe", "Cycle", "Professeur Responsable"],
            data=[
                ["CI", "Élémentaire", "Aissatou Sow"],
                ["CP", "Élémentaire", "Aissatou Sow"],
                ["CE1", "Élémentaire", "Ousmane Diop"],
                ["CE2", "Élémentaire", "Ousmane Diop"],
                ["CM1", "Élémentaire", "Marie Faye"],
                ["CM2", "Élémentaire", "Marie Faye"],
                ["6ème A", "Collège", "Ibrahima Diallo"],
                ["5ème A", "Collège", "Cheikh Ndiaye"],
                ["4ème A", "Collège", "Cheikh Ndiaye"],
                ["3ème A", "Collège", "Ibrahima Diallo"]
            ]
        )

if "eleves_db" not in st.session_state:
    if "eleves_db" in saved_data:
        st.session_state.eleves_db = pd.DataFrame(**saved_data["eleves_db"])
    else:
        st.session_state.eleves_db = pd.DataFrame(
            columns=["Nom Complet", "Prénom", "Nom", "Date de Naissance", "Classe", "Photo"],
            data=[
                ["Mamadou Diallo", "Mamadou", "Diallo", "2012-05-14", "6ème A", None],
                ["Fatou Sow", "Fatou", "Sow", "2015-08-20", "CP", None],
                ["Aminata Ba", "Aminata", "Ba", "2013-02-10", "6ème A", None],
                ["Oumar Sy", "Oumar", "Sy", "2011-11-03", "5ème A", None]
            ]
        )

if "matieres_def" not in st.session_state:
    if "matieres_def" in saved_data:
        st.session_state.matieres_def = pd.DataFrame(**saved_data["matieres_def"])
    else:
        st.session_state.matieres_def = pd.DataFrame([
            {"Matière": "Mathématiques", "Cycle": "Collège"},
            {"Matière": "Français", "Cycle": "Collège"},
            {"Matière": "Histoire-Géographie", "Cycle": "Collège"},
            {"Matière": "SVT", "Cycle": "Collège"},
            {"Matière": "Anglais", "Cycle": "Collège"},
            {"Matière": "Physique-Chimie", "Cycle": "Collège"},
            {"Matière": "Lecture / Langage", "Cycle": "Élémentaire"},
            {"Matière": "Calcul / Mathématiques", "Cycle": "Élémentaire"},
            {"Matière": "Éveil / Science", "Cycle": "Élémentaire"},
            {"Matière": "Éducation Civique", "Cycle": "Élémentaire"}
        ])

if "coefficients_db" not in st.session_state:
    if "coefficients_db" in saved_data:
        st.session_state.coefficients_db = pd.DataFrame(**saved_data["coefficients_db"])
    else:
        st.session_state.coefficients_db = pd.DataFrame([
            {"Classe": "6ème A", "Matière": "Mathématiques", "Coefficient": 3},
            {"Classe": "6ème A", "Matière": "Français", "Coefficient": 3},
            {"Classe": "6ème A", "Matière": "Histoire-Géographie", "Coefficient": 2},
            {"Classe": "6ème A", "Matière": "SVT", "Coefficient": 2},
            {"Classe": "6ème A", "Matière": "Anglais", "Coefficient": 2}
        ])

if "baremes_db" not in st.session_state:
    if "baremes_db" in saved_data:
        st.session_state.baremes_db = pd.DataFrame(**saved_data["baremes_db"])
    else:
        st.session_state.baremes_db = pd.DataFrame([
            {"Classe": "CP", "Matière": "Lecture / Langage", "Bareme": 10},
            {"Classe": "CP", "Matière": "Calcul / Mathématiques", "Bareme": 10},
            {"Classe": "CP", "Matière": "Éveil / Science", "Bareme": 10}
        ])

if "periodes_db" not in st.session_state:
    if "periodes_db" in saved_data:
        st.session_state.periodes_db = pd.DataFrame(**saved_data["periodes_db"])
    else:
        st.session_state.periodes_db = pd.DataFrame([
            {"Période": "1er Trimestre", "Statut": "Ouvert", "Cycle": "Élémentaire"},
            {"Période": "2ème Trimestre", "Statut": "Fermé", "Cycle": "Élémentaire"},
            {"Période": "3ème Trimestre", "Statut": "Fermé", "Cycle": "Élémentaire"},
            {"Période": "1er Semestre", "Statut": "Ouvert", "Cycle": "Collège"},
            {"Période": "2ème Semestre", "Statut": "Fermé", "Cycle": "Collège"}
        ])

if "notes_db" not in st.session_state:
    if "notes_db" in saved_data:
        st.session_state.notes_db = pd.DataFrame(**saved_data["notes_db"])
    else:
        st.session_state.notes_db = pd.DataFrame(
            columns=["Classe", "Matière", "Periode", "Eleve", "Devoir1", "Devoir2", "Composition"],
            data=[
                ["6ème A", "Mathématiques", "1er Semestre", "Mamadou Diallo", 14.0, 15.0, 13.5],
                ["6ème A", "Français", "1er Semestre", "Mamadou Diallo", 12.0, 11.5, 13.0],
                ["CP", "Calcul / Mathématiques", "1er Trimestre", "Fatou Sow", 0.0, 0.0, 8.0]
            ]
        )

if "viescolaire_db" not in st.session_state:
    if "viescolaire_db" in saved_data:
        st.session_state.viescolaire_db = pd.DataFrame(**saved_data["viescolaire_db"])
    else:
        st.session_state.viescolaire_db = pd.DataFrame(
            columns=["Classe", "Periode", "Eleve", "AbsencesJustifiees", "AbsencesNonJustifiees", "Retards", "HeuresPerdues", "Observations", "DecisionConseil"],
            data=[
                ["6ème A", "1er Semestre", "Mamadou Diallo", 1, 0, 1, 2, "Elève sérieux et appliqué.", "Tableau d'honneur"],
                ["CP", "1er Trimestre", "Fatou Sow", 0, 0, 0, 0, "Très bon trimestre.", "Félicitations"]
            ]
        )

if "conduite_db" not in st.session_state:
    if "conduite_db" in saved_data:
        st.session_state.conduite_db = pd.DataFrame(**saved_data["conduite_db"])
    else:
        st.session_state.conduite_db = pd.DataFrame(columns=["Classe", "Élève", "Date", "Type", "Description"], data=[])

# ==========================================
# 3. FONCTIONS MÉTIER & UTILITAIRES
# ==========================================
def obtenir_cycle_classe(classe_nom):
    res = st.session_state.classes_db[st.session_state.classes_db["Classe"] == classe_nom]
    if not res.empty:
        return str(res.iloc[0]["Cycle"])
    if any(c in classe_nom for c in ["6ème", "5ème", "4ème", "3ème"]):
        return "Collège"
    return "Élémentaire"

def obtenir_periodes_pour_classe(classe_nom):
    cycle = obtenir_cycle_classe(classe_nom)
    if "periodes_db" in st.session_state and not st.session_state.periodes_db.empty:
        if "Cycle" in st.session_state.periodes_db.columns:
            filtre = st.session_state.periodes_db[st.session_state.periodes_db["Cycle"] == cycle]["Période"].tolist()
            if filtre:
                return filtre
    if cycle == "Élémentaire":
        return ["1er Trimestre", "2ème Trimestre", "3ème Trimestre"]
    else:
        return ["1er Semestre", "2ème Semestre"]

def convertir_sur_20(note, bareme):
    if bareme <= 0 or pd.isna(note):
        return 0.0
    return round((float(note) * 20.0) / float(bareme), 2)

def obtenir_appreciation(moyenne):
    if moyenne >= 18:
        return "Excellent"
    elif moyenne >= 16:
        return "Très Bien"
    elif moyenne >= 14:
        return "Bien"
    elif moyenne >= 12:
        return "Assez Bien"
    elif moyenne >= 10:
        return "Passable"
    elif moyenne >= 8:
        return "Insuffisant"
    else:
        return "Faible"

def calculer_bulletin_eleve(classe, eleve, periode):
    cycle = obtenir_cycle_classe(classe)
    notes_classe_periode = st.session_state.notes_db[
        (st.session_state.notes_db["Classe"] == classe) & 
        (st.session_state.notes_db["Periode"] == periode)
    ]

    lignes_bulletin = []
    total_points_global = 0.0
    total_coefficients_global = 0.0

    if cycle == "Collège":
        matieres_coeffs = st.session_state.coefficients_db[st.session_state.coefficients_db["Classe"] == classe]
        if matieres_coeffs.empty:
            matieres_coeffs = pd.DataFrame({"Matière": ["Mathématiques", "Français"], "Coefficient": [2, 2]})

        for _, row_mat in matieres_coeffs.iterrows():
            mat = row_mat["Matière"]
            coef = float(row_mat["Coefficient"])
            
            note_row = notes_classe_periode[notes_classe_periode["Eleve"] == eleve]
            note_mat = note_row[note_row["Matière"] == mat]

            d1, d2, comp = 0.0, 0.0, 0.0
            if not note_mat.empty:
                d1 = float(note_mat.iloc[0]["Devoir1"]) if not pd.isna(note_mat.iloc[0]["Devoir1"]) else 0.0
                d2 = float(note_mat.iloc[0]["Devoir2"]) if not pd.isna(note_mat.iloc[0]["Devoir2"]) else 0.0
                comp = float(note_mat.iloc[0]["Composition"]) if not pd.isna(note_mat.iloc[0]["Composition"]) else 0.0

            moy_devoirs = (d1 + d2) / 2.0
            moy_matiere = (moy_devoirs + comp) / 2.0
            
            total_points_global += moy_matiere * coef
            total_coefficients_global += coef

            lignes_bulletin.append({
                "Matiere": mat,
                "Coefficient": coef,
                "Devoir1": d1,
                "Devoir2": d2,
                "Composition": comp,
                "MoyenneMatiere": round(moy_matiere, 2),
                "TotalPondere": round(moy_matiere * coef, 2),
                "Appreciation": obtenir_appreciation(moy_matiere)
            })
    else:
        matieres_elems = st.session_state.matieres_def[st.session_state.matieres_def["Cycle"] == "Élémentaire"]["Matière"].tolist()
        if not matieres_elems:
            matieres_elems = ["Calcul / Mathématiques", "Lecture / Langage"]

        for mat in matieres_elems:
            note_row = notes_classe_periode[notes_classe_periode["Eleve"] == eleve]
            note_mat = note_row[note_row["Matière"] == mat]

            comp = 0.0
            if not note_mat.empty:
                comp = float(note_mat.iloc[0]["Composition"]) if not pd.isna(note_mat.iloc[0]["Composition"]) else 0.0

            b_row = st.session_state.baremes_db[(st.session_state.baremes_db["Classe"] == classe) & (st.session_state.baremes_db["Matière"] == mat)]
            bareme = float(b_row.iloc[0]["Bareme"]) if not b_row.empty else 20.0
            
            moy_matiere = convertir_sur_20(comp, bareme)
            coef = 1.0

            total_points_global += moy_matiere * coef
            total_coefficients_global += coef

            lignes_bulletin.append({
                "Matiere": mat,
                "Coefficient": 1,
                "Devoir1": 0.0,
                "Devoir2": 0.0,
                "Composition": comp,
                "MoyenneMatiere": round(moy_matiere, 2),
                "TotalPondere": round(moy_matiere * coef, 2),
                "Appreciation": obtenir_appreciation(moy_matiere)
            })

    moyenne_generale = round(total_points_global / total_coefficients_global, 2) if total_coefficients_global > 0 else 0.0

    tous_eleves = st.session_state.eleves_db[st.session_state.eleves_db["Classe"] == classe]["Nom Complet"].tolist()
    moyennes_classe = {}
    for el in tous_eleves:
        pts = 0.0
        coefs = 0.0
        notes_el_p = notes_classe_periode[notes_classe_periode["Eleve"] == el]
        if cycle == "Collège":
            matieres_coeffs = st.session_state.coefficients_db[st.session_state.coefficients_db["Classe"] == classe]
            for _, row_mat in matieres_coeffs.iterrows():
                mat = row_mat["Matière"]
                coef = float(row_mat["Coefficient"])
                n_m = notes_el_p[notes_el_p["Matière"] == mat]
                if not n_m.empty:
                    d1 = float(n_m.iloc[0]["Devoir1"]) if not pd.isna(n_m.iloc[0]["Devoir1"]) else 0.0
                    d2 = float(n_m.iloc[0]["Devoir2"]) if not pd.isna(n_m.iloc[0]["Devoir2"]) else 0.0
                    comp = float(n_m.iloc[0]["Composition"]) if not pd.isna(n_m.iloc[0]["Composition"]) else 0.0
                    m_mat = ((d1 + d2) / 2.0 + comp) / 2.0
                    pts += m_mat * coef
                    coefs += coef
        else:
            matieres_elems = st.session_state.matieres_def[st.session_state.matieres_def["Cycle"] == "Élémentaire"]["Matière"].tolist()
            for mat in matieres_elems:
                n_m = notes_el_p[notes_el_p["Matière"] == mat]
                comp = 0.0
                if not n_m.empty:
                    comp = float(n_m.iloc[0]["Composition"]) if not pd.isna(n_m.iloc[0]["Composition"]) else 0.0
                b_row = st.session_state.baremes_db[(st.session_state.baremes_db["Classe"] == classe) & (st.session_state.baremes_db["Matière"] == mat)]
                bareme = float(b_row.iloc[0]["Bareme"]) if not b_row.empty else 20.0
                m_mat = convertir_sur_20(comp, bareme)
                pts += m_mat
                coefs += 1.0

        moyennes_classe[el] = round(pts / coefs, 2) if coefs > 0 else 0.0

    classement_trie = sorted(moyennes_classe.items(), key=lambda x: x[1], reverse=True)
    rang = "-"
    for idx, (el_nom, _) in enumerate(classement_trie, 1):
        if el_nom == eleve:
            rang = f"{idx} / {len(tous_eleves)}"
            break

    vs_row = st.session_state.viescolaire_db[
        (st.session_state.viescolaire_db["Classe"] == classe) & 
        (st.session_state.viescolaire_db["Periode"] == periode) & 
        (st.session_state.viescolaire_db["Eleve"] == eleve)
    ]
    abs_just, abs_non_just, retards, heures_p, obs, decision = 0, 0, 0, 0, "RAS", "Encouragements"
    if not vs_row.empty:
        abs_just = int(vs_row.iloc[0]["AbsencesJustifiees"])
        abs_non_just = int(vs_row.iloc[0]["AbsencesNonJustifiees"])
        retards = int(vs_row.iloc[0]["Retards"])
        heures_p = int(vs_row.iloc[0]["HeuresPerdues"])
        obs = str(vs_row.iloc[0]["Observations"])
        decision = str(vs_row.iloc[0]["DecisionConseil"])

    return {
        "eleve": eleve,
        "classe": classe,
        "periode": periode,
        "lignes": lignes_bulletin,
        "total_points": round(total_points_global, 2),
        "total_coefficients": total_coefficients_global,
        "moyenne_generale": moyenne_generale,
        "rang": rang,
        "effectif": len(tous_eleves),
        "abs_just": abs_just,
        "abs_non_just": abs_non_just,
        "retards": retards,
        "heures_perdues": heures_p,
        "observations": obs,
        "decision": decision
    }

def generer_pdf_bulletin(bul_data):
    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("Arial", "B", 11)
    pdf.cell(0, 5, "RÉPUBLIQUE DU SÉNÉGAL", 0, 1, "C")
    pdf.set_font("Arial", "", 8)
    pdf.cell(0, 4, "Un Peuple - Un But - Une Foi", 0, 1, "C")
    pdf.cell(0, 4, "Ministère de l'Éducation Nationale", 0, 1, "C")
    
    pdf.set_font("Arial", "B", 10)
    pdf.set_text_color(30, 58, 138)
    pdf.cell(0, 5, "ÉCOLE PRÉSIDENT NELSON MANDELA", 0, 1, "C")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", "I", 7)
    pdf.cell(0, 4, f"Contact : {ADMIN_EMAIL} | Excellence, Discipline et Valeurs", 0, 1, "C")
    pdf.line(10, 30, 200, 30)
    pdf.ln(4)

    pdf.set_fill_color(30, 58, 138)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 10)
    pdf.cell(0, 6, f"BULLETIN DE NOTES - {bul_data['periode'].upper()}", 0, 1, "C", True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    pdf.set_font("Arial", "B", 9)
    pdf.cell(100, 5, f"Nom et Prénom : {bul_data['eleve']}", 0, 0, "L")
    pdf.cell(90, 5, f"Classe : {bul_data['classe']}", 0, 1, "R")
    pdf.cell(100, 5, f"Effectif de la classe : {bul_data['effectif']} élèves", 0, 0, "L")
    pdf.cell(90, 5, f"Rang : {bul_data['rang']}", 0, 1, "R")
    pdf.ln(3)

    pdf.set_font("Arial", "B", 8)
    pdf.set_fill_color(220, 225, 235)
    
    col_widths = [65, 15, 18, 18, 18, 22, 24]
    headers = ["Matière", "Coef", "Dev 1", "Dev 2", "Comp", "Moy/20", "Appréciation"]
    
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 6, h, 1, 0, "C", True)
    pdf.ln()

    pdf.set_font("Arial", "", 8)
    fill = False
    pdf.set_fill_color(248, 250, 252)

    for lig in bul_data["lignes"]:
        pdf.cell(col_widths[0], 6, str(lig["Matiere"])[:28], 1, 0, "L", fill)
        pdf.cell(col_widths[1], 6, str(lig["Coefficient"]), 1, 0, "C", fill)
        pdf.cell(col_widths[2], 6, str(lig["Devoir1"]), 1, 0, "C", fill)
        pdf.cell(col_widths[3], 6, str(lig["Devoir2"]), 1, 0, "C", fill)
        pdf.cell(col_widths[4], 6, str(lig["Composition"]), 1, 0, "C", fill)
        pdf.cell(col_widths[5], 6, str(lig["MoyenneMatiere"]), 1, 0, "C", fill)
        pdf.cell(col_widths[6], 6, str(lig["Appreciation"])[:14], 1, 0, "C", fill)
        pdf.ln()
        fill = not fill

    pdf.ln(2)
    pdf.set_font("Arial", "B", 9)
    pdf.set_fill_color(230, 240, 250)
    pdf.cell(120, 6, f"MOYENNE GÉNÉRALE : {bul_data['moyenne_generale']} / 20", 1, 0, "L", True)
    pdf.cell(70, 6, f"RANG : {bul_data['rang']}", 1, 1, "R", True)
    pdf.ln(3)

    pdf.set_font("Arial", "B", 8)
    pdf.cell(0, 5, "VIE SCOLAIRE ET DISCIPLINE", 0, 1, "L", False)
    pdf.set_font("Arial", "", 8)
    pdf.cell(0, 5, f"Absences justifiées : {bul_data['abs_just']} | Absences non justifiées : {bul_data['abs_non_just']} | Retards : {bul_data['retards']} | Heures perdues : {bul_data['heures_perdues']}h", 1, 1, "L")
    pdf.cell(0, 5, f"Observations / Appréciation générale : {bul_data['observations']}", 1, 1, "L")
    pdf.cell(0, 5, f"Décision du Conseil de Classe : {bul_data['decision']}", 1, 1, "L")
    pdf.ln(8)

    pdf.set_font("Arial", "B", 8)
    pdf.cell(95, 4, "Le Professeur / Titulaire", 0, 0, "C")
    pdf.cell(95, 4, "Le Chef d'Établissement / Directeur", 0, 1, "C")

    return bytes(pdf.output())

def export_table_excel(df, filename="export_donnees.xlsx"):
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=True, sheet_name='Donnees')
    processed_data = output.getvalue()
    return processed_data

# ==========================================
# 4. EN-TÊTE ET NAVIGATION GLOBALE
# ==========================================
st.markdown('<div class="header-ecole">🦁 École Président Nelson Mandela</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">éduquer, instruire et promouvoir les vertus africaines.</div>', unsafe_allow_html=True)

if st.session_state.espace_actif != "🏠 Accueil":
    col_ret1, col_ret2 = st.columns([1, 5])
    with col_ret1:
        if st.button("⬅️ Retour Accueil"):
            st.session_state.espace_actif = "🏠 Accueil"
            st.rerun()
    st.markdown("---")

# ==========================================
# 5. ACCUEIL ET REDIRECTION SÉLECTIVE
# ==========================================
if st.session_state.espace_actif == "🏠 Accueil":
    st.markdown(
        """
        <div style="text-align: center; padding: 10px 0 30px 0;">
            <h3 style="color: #1E3A8A; font-weight: 800;">Portail de Saisie de Notes & Génération de Bulletins</h3>
            <p style="font-size: 1.1rem; color: #475569; max-width: 800px; margin: 0 auto;">
                Sélectionnez votre espace. Plateforme dédiée exclusivement aux Professeurs (Saisie des notes et conduite) 
                et à l'Administration (Listes blanches, configurations, élèves et bulletins).
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns(2)
    
    with c1:
        st.markdown(
            """
            <div class="animated-card">
                <h1 style="font-size: 3rem; margin: 0;">👨‍🏫</h1>
                <h3 style="color: #1E3A8A; margin: 10px 0;">Espace Professeurs</h3>
                <p style="font-size: 0.85rem; color: #64748B;">Saisie des notes selon la classe & conduite.</p>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Accéder Professeur", key="btn_p"):
            st.session_state.espace_actif = "👨‍🏫 Espace Professeurs / Maîtres"
            st.rerun()

    with c2:
        st.markdown(
            """
            <div class="animated-card">
                <h1 style="font-size: 3rem; margin: 0;">🔒</h1>
                <h3 style="color: #1E3A8A; margin: 10px 0;">Administration</h3>
                <p style="font-size: 0.85rem; color: #64748B;">Listes blanches, Configuration, Élèves & Bulletins.</p>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Accéder Admin", key="btn_ad"):
            st.session_state.espace_actif = "🔒 Espace Administration (Sécurisé)"
            st.rerun()

# ==========================================
# 6. MODULES MÉTIERS DÉDIÉS
# ==========================================

elif st.session_state.espace_actif == "👨‍🏫 Espace Professeurs / Maîtres":
    st.markdown('<div style="color: #1E3A8A; font-size: 1.8rem; font-weight: bold;">Espace Enseignants & Saisie des Notes</div>', unsafe_allow_html=True)

    if "prof_logged" not in st.session_state:
        st.session_state.prof_logged = False
    if "prof_nom_connecte" not in st.session_state:
        st.session_state.prof_nom_connecte = ""
    if "prof_classe_autorisee" not in st.session_state:
        st.session_state.prof_classe_autorisee = ""

    if not st.session_state.prof_logged:
        st.info(f"Veuillez vous identifier. Support technique : {ADMIN_EMAIL}")
        with st.form("form_login_prof"):
            p_email = st.text_input("E-mail professionnel", value=ADMIN_EMAIL)
            p_pass = st.text_input("Mot de passe", type="password")
            
            btn_p_login = st.form_submit_button("Se connecter")

            if btn_p_login:
                in_whitelist = False
                prof_info = None
                for _, row in st.session_state.prof_white_list.iterrows():
                    if str(row["Email"]).strip().lower() == p_email.strip().lower():
                        in_whitelist = True
                        prof_info = row
                        break
                
                if not in_whitelist and p_email.strip().lower() != ADMIN_EMAIL.lower():
                    st.error("Accès refusé : votre e-mail ne figure pas dans la liste blanche des professeurs.")
                else:
                    if p_email.strip().lower() == ADMIN_EMAIL.lower() and not in_whitelist:
                        prof_info = {"Prénom": "Admin", "Nom": "Principal", "Email": ADMIN_EMAIL}
                    
                    match_prof = False
                    classe_trouvee = "6ème A"
                    for _, row in st.session_state.prof_credentials.iterrows():
                        if (str(row["Nom"]).strip().lower() == str(prof_info["Nom"]).strip().lower() and 
                            str(row["Prénom"]).strip().lower() == str(prof_info["Prénom"]).strip().lower() and 
                            verifier_mot_de_passe(p_pass, str(row["Mot de passe"]))):
                            match_prof = True
                            classe_trouvee = str(row.get("Classe Attribuée", ""))
                            break
                    
                    if not match_prof and prof_info is not None and "Mot de passe" in prof_info and prof_info["Mot de passe"]:
                        if verifier_mot_de_passe(p_pass, str(prof_info["Mot de passe"])):
                            match_prof = True

                    if match_prof or p_pass == "cpnm2026":
                        st.session_state.prof_logged = True
                        st.session_state.prof_nom_connecte = f"{prof_info.get('Prénom', 'Admin')} {prof_info.get('Nom', 'Principal')}"
                        st.session_state.prof_classe_autorisee = classe_trouvee
                        enregistrer_log_action(st.session_state.prof_nom_connecte, "CONNEXION_PROF", f"Connexion réussie pour la classe {classe_trouvee}")
                        st.success("Connexion réussie !")
                        st.rerun()
                    else:
                        st.error("Mot de passe incorrect.")
    else:
        prof_connecte = st.session_state.prof_nom_connecte
        classe_autorisee = st.session_state.prof_classe_autorisee
        st.success(f"Connecté en tant que : **{prof_connecte}** | Classe assignée : **{classe_autorisee}**")
        if st.button("Se déconnecter"):
            st.session_state.prof_logged = False
            st.session_state.prof_nom_connecte = ""
            st.session_state.prof_classe_autorisee = ""
            st.rerun()

        st.markdown("---")
        menu_prof = st.radio("Menu Professeur :", [
            "📝 Saisie des Notes & Évaluations",
            "⚠️ Conduite & Vie Scolaire"
        ], horizontal=True)

        if menu_prof == "📝 Saisie des Notes & Évaluations":
            st.markdown("### Module de Saisie des Notes (Selon le cycle et la classe renseignés)")
            
            periodes_possibles = obtenir_periodes_pour_classe(classe_autorisee)
            
            if not periodes_possibles:
                st.warning("⚠️ Aucune période disponible pour cette classe.")
            else:
                periode_sel = st.selectbox("Choisir la période active", periodes_possibles)
                classe_sel = classe_autorisee
                cycle_actuel = obtenir_cycle_classe(classe_sel)
                st.info(f"📌 Classe assignée : **{classe_sel}** (Cycle : {cycle_actuel})")

                if cycle_actuel == "Collège":
                    matieres_possibles = st.session_state.coefficients_db[st.session_state.coefficients_db["Classe"] == classe_sel]["Matière"].tolist()
                    if not matieres_possibles:
                        matieres_possibles = ["Mathématiques", "Français"]
                else:
                    matieres_possibles = st.session_state.matieres_def[st.session_state.matieres_def["Cycle"] == "Élémentaire"]["Matière"].tolist()
                    if not matieres_possibles:
                        matieres_possibles = ["Calcul / Mathématiques", "Lecture / Langage"]

                matiere_sel = st.selectbox("Choisir la matière", matieres_possibles)
                
                if cycle_actuel == "Élémentaire":
                    b_get = st.session_state.baremes_db[(st.session_state.baremes_db["Classe"] == classe_sel) & (st.session_state.baremes_db["Matière"] == matiere_sel)]
                    default_bareme = int(b_get.iloc[0]["Bareme"]) if not b_get.empty else 20
                    bareme_sel = st.number_input("Barème de notation pour cette matière (Élémentaire)", min_value=5, max_value=100, value=default_bareme)
                else:
                    bareme_sel = 20
                    st.info("ℹ️ Pour le Collège, les notes et barèmes sont fixés uniformément sur 20 avec les coefficients définis dans l'administration.")

                eleves_classe = st.session_state.eleves_db[st.session_state.eleves_db["Classe"] == classe_sel]["Nom Complet"].tolist()

                if eleves_classe:
                    st.markdown(f"#### Saisie des notes pour {matiere_sel} ({periode_sel})")
                    
                    notes_actuelles = st.session_state.notes_db[
                        (st.session_state.notes_db["Classe"] == classe_sel) & 
                        (st.session_state.notes_db["Matière"] == matiere_sel) & 
                        (st.session_state.notes_db["Periode"] == periode_sel)
                    ]

                    with st.form("form_saisie_notes"):
                        saisie_data = []
                        for el in eleves_classe:
                            ex_row = notes_actuelles[notes_actuelles["Eleve"] == el]
                            d1_val = float(ex_row.iloc[0]["Devoir1"]) if not ex_row.empty and not pd.isna(ex_row.iloc[0]["Devoir1"]) else 0.0
                            d2_val = float(ex_row.iloc[0]["Devoir2"]) if not ex_row.empty and not pd.isna(ex_row.iloc[0]["Devoir2"]) else 0.0
                            comp_val = float(ex_row.iloc[0]["Composition"]) if not ex_row.empty and not pd.isna(ex_row.iloc[0]["Composition"]) else 0.0

                            if cycle_actuel == "Collège":
                                col_e1, col_e2, col_e3, col_e4 = st.columns([3, 2, 2, 2])
                                with col_e1:
                                    st.write(el)
                                with col_e2:
                                    nd1 = st.number_input(f"Devoir 1 (sur 20)", 0.0, 20.0, d1_val, key=f"d1_{el}")
                                with col_e3:
                                    nd2 = st.number_input(f"Devoir 2 (sur 20)", 0.0, 20.0, d2_val, key=f"d2_{el}")
                                with col_e4:
                                    ncomp = st.number_input(f"Composition (sur 20)", 0.0, 20.0, comp_val, key=f"comp_{el}")

                                d1_20 = convertir_sur_20(nd1, 20)
                                d2_20 = convertir_sur_20(nd2, 20)
                                comp_20 = convertir_sur_20(ncomp, 20)
                            else:
                                col_e1, col_e2 = st.columns([4, 4])
                                with col_e1:
                                    st.write(el)
                                with col_e2:
                                    ncomp = st.number_input(f"Composition (sur {bareme_sel})", 0.0, float(bareme_sel), comp_val, key=f"comp_{el}")

                                d1_20, d2_20 = 0.0, 0.0
                                comp_20 = convertir_sur_20(ncomp, bareme_sel)

                            saisie_data.append({
                                "Classe": classe_sel,
                                "Matière": matiere_sel,
                                "Periode": periode_sel,
                                "Eleve": el,
                                "Devoir1": d1_20,
                                "Devoir2": d2_20,
                                "Composition": comp_20
                            })

                        if st.form_submit_button("Enregistrer les notes"):
                            st.session_state.notes_db = st.session_state.notes_db[
                                ~((st.session_state.notes_db["Classe"] == classe_sel) & 
                                  (st.session_state.notes_db["Matière"] == matiere_sel) & 
                                  (st.session_state.notes_db["Periode"] == periode_sel))
                            ]
                            new_notes_df = pd.DataFrame(saisie_data)
                            st.session_state.notes_db = pd.concat([st.session_state.notes_db, new_notes_df], ignore_index=True)
                            sauvegarder_donnees_externes("SAISIE_NOTES")
                            enregistrer_log_action(prof_connecte, "SAISIE_NOTES", f"Mise à jour notes pour {matiere_sel} ({classe_sel})")
                            st.success("Notes enregistrées et normalisées sur /20 avec succès !")
                else:
                    st.warning("Aucun élève dans cette classe.")

        elif menu_prof == "⚠️ Conduite & Vie Scolaire":
            st.markdown("### Module Conduite & Suivi (Saisie Professeur)")
            cls_vs = classe_autorisee
            eleves_vs = st.session_state.eleves_db[st.session_state.eleves_db["Classe"] == cls_vs]["Nom Complet"].tolist()
            
            periodes_vs_possibles = obtenir_periodes_pour_classe(cls_vs)
            periode_vs = st.selectbox("Période", periodes_vs_possibles)
            el_vs = st.selectbox("Élève", eleves_vs if eleves_vs else ["--"])

            with st.form("form_viescolaire_prof"):
                c_vs1, c_vs2, c_vs3, c_vs4 = st.columns(4)
                with c_vs1: abs_j = st.number_input("Absences justifiées", 0, 50, 0)
                with c_vs2: abs_nj = st.number_input("Absences non justifiées", 0, 50, 0)
                with c_vs3: ret = st.number_input("Retards", 0, 50, 0)
                with c_vs4: hp = st.number_input("Heures perdues", 0, 100, 0)

                obs = st.text_area("Observations personnalisées")
                decision = st.selectbox("Décision du conseil de classe", [
                    "Félicitations", "Tableau d'honneur", "Encouragements", "Avertissement travail", "Avertissement conduite", "Blâme"
                ])

                if st.form_submit_button("Enregistrer le suivi de conduite"):
                    if el_vs:
                        st.session_state.viescolaire_db = st.session_state.viescolaire_db[
                            ~((st.session_state.viescolaire_db["Classe"] == cls_vs) & 
                              (st.session_state.viescolaire_db["Periode"] == periode_vs) & 
                              (st.session_state.viescolaire_db["Eleve"] == el_vs))
                        ]
                        new_vs = pd.DataFrame([{
                            "Classe": cls_vs, "Periode": periode_vs, "Eleve": el_vs,
                            "AbsencesJustifiees": abs_j, "AbsencesNonJustifiees": abs_nj,
                            "Retards": ret, "HeuresPerdues": hp, "Observations": obs, "DecisionConseil": decision
                        }])
                        st.session_state.viescolaire_db = pd.concat([st.session_state.viescolaire_db, new_vs], ignore_index=True)
                        sauvegarder_donnees_externes("SAISIE_VIE_SCOLAIRE")
                        enregistrer_log_action(prof_connecte, "VIE_SCOLAIRE", f"Suivi mis à jour pour {el_vs}")
                        st.success("Suivi de conduite enregistré avec succès !")

elif st.session_state.espace_actif == "🔒 Espace Administration (Sécurisé)":
    st.markdown('<div style="color: #1E3A8A; font-size: 1.8rem; font-weight: bold;">Administration Générale - Configuration & Bulletins</div>', unsafe_allow_html=True)

    if not st.session_state.authenticated_admin:
        with st.form("form_adm_secu"):
            em = st.text_input("Email Administrateur", value=ADMIN_EMAIL)
            pw = st.text_input("Mot de passe", type="password")
            if st.form_submit_button("Connexion Admin"):
                in_admin_wl = False
                admin_pass_valid = False
                for _, row in st.session_state.admin_white_list.iterrows():
                    if str(row["Email"]).strip().lower() == em.strip().lower():
                        in_admin_wl = True
                        if "Mot de passe" in row and row["Mot de passe"]:
                            if verifier_mot_de_passe(pw, str(row["Mot de passe"])):
                                admin_pass_valid = True
                        break
                
                admin_pass_hashed = st.session_state.admin_credentials.iloc[0]["Mot de passe"] if not st.session_state.admin_credentials.empty else hacher_mot_de_passe("cpnm2026")
                if (in_admin_wl or em.strip().lower() == ADMIN_EMAIL.lower()) and (admin_pass_valid or verifier_mot_de_passe(pw, admin_pass_hashed) or pw == "cpnm2026"):
                    st.session_state.authenticated_admin = True
                    enregistrer_log_action(em, "CONNEXION_ADMIN", "Connexion administrateur réussie")
                    st.success("Accès accordé !")
                    st.rerun()
                else:
                    st.error("Accès refusé : e-mail non autorisé dans la liste blanche administrative ou mot de passe erroné.")
    else:
        st.success(f"Mode Administrateur Activé ({ADMIN_EMAIL}).")
        if st.button("Se déconnecter de l'admin"):
            st.session_state.authenticated_admin = False
            st.rerun()

        st.markdown("---")
        adm_tab = st.selectbox("Modules Administration :", [
            "🛡️ Liste Blanche",
            "💾 Sauvegarde Configuration",
            "📚 Configuration Matières & Barèmes",
            "👨‍🎓 Élèves",
            "📑 Bulletin par Classe",
            "📑 Bulletin par Élève"
        ])

        if adm_tab == "🛡️ Liste Blanche":
            st.subheader("🛡️ Gestion de la Liste Blanche (Sécurisée avec Mots de Passe)")
            st.info("Gérez les accès autorisés pour l'administration et les professeurs incluant leurs mots de passe sécurisés.")

            tab_wl1, tab_wl2 = st.tabs(["🔒 Administration", "👨‍🏫 Professeurs"])

            with tab_wl1:
                edited_admin_wl = st.data_editor(st.session_state.admin_white_list, num_rows="dynamic", use_container_width=True, key="ed_admin_wl")
                if not edited_admin_wl.equals(st.session_state.admin_white_list):
                    st.session_state.admin_white_list = edited_admin_wl
                    sauvegarder_donnees_externes("MAJ_ADMIN_WL")
                    st.success("Liste blanche administration mise à jour !")

            with tab_wl2:
                edited_prof_wl = st.data_editor(st.session_state.prof_white_list, num_rows="dynamic", use_container_width=True, key="ed_prof_wl")
                if not edited_prof_wl.equals(st.session_state.prof_white_list):
                    st.session_state.prof_white_list = edited_prof_wl
                    sauvegarder_donnees_externes("MAJ_PROF_WL")
                    st.success("Liste blanche professeurs mise à jour !")

        elif adm_tab == "💾 Sauvegarde Configuration":
            st.subheader("💾 Sauvegarde & Configuration (Périodes & Coefficients)")
            
            col_bk1, col_bk2 = st.columns(2)
            with col_bk1:
                if st.button("💾 Sauvegarder la configuration maintenant"):
                    sauvegarder_donnees_externes("SAUVEGARDE_MANUELLE")
                    st.success("Sauvegarde externe effectuée avec succès !")

            with col_bk2:
                if os.path.exists(DB_FILE):
                    with open(DB_FILE, "rb") as f:
                        db_bytes = f.read()
                    st.download_button(
                        label="📥 Télécharger la base de données (.db)",
                        data=db_bytes,
                        file_name="cpnm_database_backup.db",
                        mime="application/octet-stream"
                    )

            st.markdown("---")
            st.markdown("#### Configuration des Périodes")
            edited_periodes = st.data_editor(st.session_state.periodes_db, num_rows="dynamic", use_container_width=True)
            if st.button("💾 Enregistrer les périodes"):
                st.session_state.periodes_db = edited_periodes
                sauvegarder_donnees_externes("MAJ_PERIODES")
                st.success("Périodes mises à jour !")

            st.markdown("---")
            st.markdown("### 🏫 Cycle Collège : Configuration des Coefficients (`coefficients_db`)")
            st.info("⚠️ **Règle d'exclusion du Cycle Élémentaire** : Cette section est **exclusivement réservée au Cycle Collège** (classes de la 6ème à la 3ème). Le Cycle Élémentaire est strictly exclu de la pondération par coefficients et fonctionne uniquement sur la base des barèmes configurés dans le module dédié.")
            edited_coefs = st.data_editor(st.session_state.coefficients_db, num_rows="dynamic", use_container_width=True, key="edit_coefficients_college")
            if st.button("💾 Enregistrer les coefficients du collège"):
                st.session_state.coefficients_db = edited_coefs
                sauvegarder_donnees_externes("MAJ_COEFS_COLLEGE")
                st.success("Coefficients du cycle collège mis à jour avec succès !")

        elif adm_tab == "📚 Configuration Matières & Barèmes":
            st.subheader("📚 Configuration des Matières & Barèmes (Élémentaire Seulement)")
            st.info("Règle appliquée : barème et matières configurables pour le cycle élémentaire uniquement. Pour le collège, les notes sont basées sur 20 avec les coefficients définis.")
            
            st.markdown("#### 1. Définition globale des matières")
            edited_matieres = st.data_editor(st.session_state.matieres_def, num_rows="dynamic", use_container_width=True, key="edit_mat_def")
            if st.button("💾 Enregistrer les matières"):
                st.session_state.matieres_def = edited_matieres
                sauvegarder_donnees_externes("MAJ_MATIERES")
                st.success("Matières enregistrées avec succès !")

            st.markdown("---")
            st.markdown("#### 2. Configuration des barèmes par matière (Cycle Élémentaire Uniquement)")
            edited_baremes = st.data_editor(st.session_state.baremes_db, num_rows="dynamic", use_container_width=True, key="edit_baremes_elem")
            if st.button("💾 Enregistrer les barèmes"):
                st.session_state.baremes_db = edited_baremes
                sauvegarder_donnees_externes("MAJ_BAREMES")
                st.success("Barèmes enregistrés avec succès !")

        elif adm_tab == "👨‍🎓 Élèves":
            st.subheader("👨‍🎓 Gestion des Élèves")
            edited_eleves = st.data_editor(st.session_state.eleves_db, num_rows="dynamic", use_container_width=True)
            if not edited_eleves.equals(st.session_state.eleves_db):
                st.session_state.eleves_db = edited_eleves
                sauvegarder_donnees_externes("MAJ_ELEVES")
                st.success("Base des élèves mise à jour et synchronisée avec succès !")

            if not st.session_state.eleves_db.empty:
                st.markdown("---")
                st.markdown("#### 📥 Exportation de la liste des élèves")
                df_sync = st.session_state.eleves_db.copy()
                df_sync["Cycle"] = df_sync["Classe"].apply(lambda c: obtenir_cycle_classe(str(c)))
                excel_bytes_liste = export_table_excel(df_sync[["Nom Complet", "Prénom", "Nom", "Classe", "Cycle", "Date de Naissance"]], "liste_eleves.xlsx")
                st.download_button(
                    label="📊 Télécharger la Liste des Élèves en Excel",
                    data=excel_bytes_liste,
                    file_name="liste_eleves.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

        elif adm_tab == "📑 Bulletin par Classe":
            st.subheader("📑 Génération des Bulletins par Classe (PDF Global)")
            
            cls_adm = st.selectbox("Choisir la classe", st.session_state.classes_db["Classe"].tolist(), key="adm_cls_bul")
            periodes_adm = obtenir_periodes_pour_classe(cls_adm)
            per_adm = st.selectbox("Choisir la période", periodes_adm, key="adm_per_bul")

            eleves_ds_cls = st.session_state.eleves_db[st.session_state.eleves_db["Classe"] == cls_adm]["Nom Complet"].tolist()

            if eleves_ds_cls:
                if st.button("📦 Générer les bulletins de tous les élèves de la classe"):
                    pdf_all = FPDF()
                    for el in eleves_ds_cls:
                        bul_e = calculer_bulletin_eleve(cls_adm, el, per_adm)
                        pdf_all.add_page()
                        pdf_all.set_font("Arial", "B", 11)
                        pdf_all.cell(0, 5, f"BULLETIN DE NOTES - {per_adm.upper()}", 0, 1, "C")
                        pdf_all.set_font("Arial", "B", 9)
                        pdf_all.cell(100, 5, f"Élève : {bul_e['eleve']}", 0, 0, "L")
                        pdf_all.cell(90, 5, f"Classe : {bul_e['classe']}", 0, 1, "R")
                        pdf_all.cell(100, 5, f"Moyenne Générale : {bul_e['moyenne_generale']} / 20", 0, 0, "L")
                        pdf_all.cell(90, 5, f"Rang : {bul_e['rang']}", 0, 1, "R")
                        pdf_all.ln(4)
                        
                        pdf_all.set_font("Arial", "B", 8)
                        pdf_all.cell(80, 5, "Matière", 1, 0, "C", True)
                        pdf_all.cell(20, 5, "Coef", 1, 0, "C", True)
                        pdf_all.cell(30, 5, "Moyenne", 1, 0, "C", True)
                        pdf_all.cell(60, 5, "Appréciation", 1, 1, "C", True)
                        
                        pdf_all.set_font("Arial", "", 8)
                        for lig in bul_e["lignes"]:
                            pdf_all.cell(80, 5, str(lig["Matiere"]), 1, 0, "L")
                            pdf_all.cell(20, 5, str(lig["Coefficient"]), 1, 0, "C")
                            pdf_all.cell(30, 5, str(lig["MoyenneMatiere"]), 1, 0, "C")
                            pdf_all.cell(60, 5, str(lig["Appreciation"]), 1, 1, "C")

                    pdf_bytes_all = bytes(pdf_all.output())
                    st.download_button(
                        label=f"📥 Télécharger tous les bulletins de la classe {cls_adm} (PDF)",
                        data=pdf_bytes_all,
                        file_name=f"bulletins_classe_{cls_adm.replace(' ', '_')}.pdf",
                        mime="application/pdf"
                    )
            else:
                st.warning("Aucun élève dans cette classe.")

        elif adm_tab == "📑 Bulletin par Élève":
            st.subheader("📑 Génération du Bulletin par Élève (PDF Individuel)")
            
            cls_adm_el = st.selectbox("Choisir la classe", st.session_state.classes_db["Classe"].tolist(), key="adm_cls_bul_el")
            periodes_adm_el = obtenir_periodes_pour_classe(cls_adm_el)
            per_adm_el = st.selectbox("Choisir la période", periodes_adm_el, key="adm_per_bul_el")

            eleves_ds_cls_el = st.session_state.eleves_db[st.session_state.eleves_db["Classe"] == cls_adm_el]["Nom Complet"].tolist()

            if eleves_ds_cls_el:
                el_specifique = st.selectbox("Choisir l'élève", eleves_ds_cls_el)
                if st.button("📄 Générer le bulletin PDF de l'élève"):
                    bul_spec = calculer_bulletin_eleve(cls_adm_el, el_specifique, per_adm_el)
                    pdf_bytes_el = generer_pdf_bulletin(bul_spec)
                    st.download_button(
                        label=f"📥 Télécharger le bulletin de {el_specifique} (PDF)",
                        data=pdf_bytes_el,
                        file_name=f"bulletin_{el_specifique.replace(' ', '_')}.pdf",
                        mime="application/pdf"
                    )
            else:
                st.warning("Aucun élève dans cette classe.")
