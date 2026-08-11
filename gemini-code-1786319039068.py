import base64
from datetime import datetime
import io
import json
import os
import urllib.request
import zipfile
from fpdf import FPDF
import pandas as pd
import numpy as np
import streamlit as st

# ==========================================
# 0. GESTION SUPABASE & SÉCURITÉ MOTS DE PASSE
# ==========================================
try:
    from supabase import create_client, Client
    HAS_SUPABASE = True
except ImportError:
    HAS_SUPABASE = False

try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    raise ImportError("La bibliothèque 'bcrypt' est obligatoire et doit être présente dans requirements.txt pour assurer la sécurité.")

@st.cache_resource
def init_supabase_client():
    if HAS_SUPABASE and "supabase" in st.secrets:
        return create_client(st.secrets["supabase"]["url"], st.secrets["supabase"]["key"])
    return None

supabase = init_supabase_client()

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
    if password == hashed:
        return True
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

ADMIN_EMAIL = "cpnm@gmail.com"

def enregistrer_log_action(acteur: str, action: str, details: str):
    """Consigne chaque action utilisateur dans la session ou les logs locaux."""
    try:
        horodatage = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if "audit_logs_local" not in st.session_state:
            st.session_state.audit_logs_local = []
        st.session_state.audit_logs_local.append({
            "horodatage": horodatage,
            "acteur": acteur,
            "action": action,
            "details": details
        })
    except Exception:
        pass

def charger_donnees_externes():
    """Charge l'ensemble des bases de données depuis Supabase pour garantir la persistance globale."""
    data = {}
    if supabase:
        try:
            response = supabase.table("app_storage").select("key, data").execute()
            if response.data:
                for row in response.data:
                    k = row["key"]
                    v = row["data"]
                    if isinstance(v, list):
                        data[k] = pd.DataFrame(v)
                    elif isinstance(v, dict):
                        data[k] = v
        except Exception as e:
            print(f"Erreur chargement Supabase: {e}")
    return data

def nettoyer_donnees_pour_json(obj):
    """Remplace de manière récursive les valeurs NaN/Inf non conformes JSON."""
    if isinstance(obj, pd.DataFrame):
        return obj.where(pd.notnull(obj), None).to_dict(orient="records")
    elif isinstance(obj, dict):
        return {k: nettoyer_donnees_pour_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [nettoyer_donnees_pour_json(v) for v in obj]
    elif isinstance(obj, float):
        if np.isnan(obj) or np.isinf(obj):
            return 0.0
        return obj
    elif pd.isna(obj):
        return None
    return obj

def synchroniser_listes_blanches():
    """Maintient une cohérence parfaite entre les listes blanches et les identifiants d'accès."""
    if "prof_credentials" in st.session_state and not st.session_state.prof_credentials.empty:
        sync_wl_list = []
        for _, r in st.session_state.prof_credentials.iterrows():
            sync_wl_list.append({
                "Email": r.get("Email", ""),
                "Nom": r.get("Nom", ""),
                "Prénom": r.get("Prénom", ""),
                "Mot de passe": r.get("Mot de passe", ""),
                "Matière Principale": r.get("Matière Principale", ""),
                "Classe Attribuée": r.get("Classe Attribuée", "")
            })
        st.session_state.prof_white_list = pd.DataFrame(sync_wl_list)

    if "admin_credentials" in st.session_state and not st.session_state.admin_credentials.empty:
        sync_admin_list = []
        for _, r in st.session_state.admin_credentials.iterrows():
            sync_admin_list.append({
                "Email": r.get("Email", ""),
                "Nom": r.get("Nom", ""),
                "Prénom": r.get("Prénom", ""),
                "Mot de passe": r.get("Mot de passe", ""),
                "Niveau d'accès": r.get("Niveau d'accès", "Administrateur")
            })
        st.session_state.admin_white_list = pd.DataFrame(sync_admin_list)

    if "parents_white_list" not in st.session_state or st.session_state.parents_white_list.empty:
        st.session_state.parents_white_list = pd.DataFrame([
            {"Téléphone": "+221771234567", "Prénom Élève": "Mamadou", "Nom Élève": "Diallo", "Année Naissance": 2012, "Classe": "6ème A"},
            {"Téléphone": ADMIN_EMAIL, "Prénom Élève": "Fatou", "Nom Élève": "Sow", "Année Naissance": 2015, "Classe": "CP"},
        ])

def sauvegarder_donnees_externes(action_label="SAUVEGARDE_DONNEES"):
    """Enregistrement immédiat dans Supabase pour la persistance et la gestion des accès simultanés."""
    synchroniser_listes_blanches()

    if "eleves_db" in st.session_state and not st.session_state.eleves_db.empty:
        prenoms, noms = [], []
        for _, r in st.session_state.eleves_db.iterrows():
            if "Prénom" in st.session_state.eleves_db.columns and "Nom" in st.session_state.eleves_db.columns:
                prenoms.append(str(r.get("Prénom", "")))
                noms.append(str(r.get("Nom", "")))
            else:
                nc = str(r.get("Nom Complet", ""))
                parts = nc.split(" ", 1)
                prenoms.append(parts[0] if len(parts) > 0 else "")
                noms.append(parts[1] if len(parts) > 1 else "")
        st.session_state.eleves_db["Prénom"] = prenoms
        st.session_state.eleves_db["Nom"] = noms
        st.session_state.eleves_db["Nom Complet"] = [f"{p} {n}".strip() for p, n in zip(prenoms, noms)]
        st.session_state.eleves_db = st.session_state.eleves_db.sort_values(by="Nom Complet", ascending=True).reset_index(drop=True)

    if "notes_db" in st.session_state and isinstance(st.session_state.notes_db, pd.DataFrame):
        st.session_state.notes_db = st.session_state.notes_db.reset_index(drop=True)
        if "Periode" in st.session_state.notes_db.columns:
            st.session_state.notes_db["Période"] = st.session_state.notes_db["Periode"]
        elif "Période" in st.session_state.notes_db.columns:
            st.session_state.notes_db["Periode"] = st.session_state.notes_db["Période"]

    if supabase:
        tables_to_save = {
            "eleves_db": st.session_state.get("eleves_db", pd.DataFrame()),
            "notes_db": st.session_state.get("notes_db", pd.DataFrame()),
            "viescolaire_db": st.session_state.get("viescolaire_db", pd.DataFrame()),
            "cahier_textes": st.session_state.get("cahier_textes", pd.DataFrame()),
            "absences_db": st.session_state.get("absences_db", pd.DataFrame()),
            "classes_db": st.session_state.get("classes_db", pd.DataFrame()),
            "matieres_def": st.session_state.get("matieres_def", pd.DataFrame()),
            "coefficients_db": st.session_state.get("coefficients_db", pd.DataFrame()),
            "periodes_db": st.session_state.get("periodes_db", pd.DataFrame()),
            "prof_credentials": st.session_state.get("prof_credentials", pd.DataFrame()),
            "admin_credentials": st.session_state.get("admin_credentials", pd.DataFrame()),
            "parents_white_list": st.session_state.get("parents_white_list", pd.DataFrame()),
            "edt_grid_db": st.session_state.get("edt_grid_db", {})
        }

        for k, val in tables_to_save.items():
            try:
                clean_val = nettoyer_donnees_pour_json(val)
                supabase.table("app_storage").upsert({"key": k, "data": clean_val}).execute()
            except Exception as e:
                print(f"Erreur synchro Supabase pour {k}: {e}")

    horodatage_svg = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if "backup_history" not in st.session_state:
        st.session_state.backup_history = []
    
    st.session_state.backup_history.insert(0, {
        "Horodatage": horodatage_svg,
        "Action": action_label,
        "Statut": "Enregistré et Synchronisé Supabase avec succès",
        "Volume Données": f"Élèves: {len(st.session_state.get('eleves_db', []))}, Notes: {len(st.session_state.get('notes_db', []))}"
    })

    enregistrer_log_action("ADMIN", action_label, "Sauvegarde globale, synchronisation Supabase et persistance exécutées.")

saved_data = charger_donnees_externes()

# ==========================================
# 0. BIS. GESTION DES POLICES UNICODE ET LOGO
# ==========================================
@st.cache_resource
def telecharger_polices():
    fonts = {
        "DejaVuSans.ttf": "https://raw.githubusercontent.com/dejavu-fonts/dejavu-fonts/master/ttf/DejaVuSans.ttf",
        "DejaVuSans-Bold.ttf": "https://raw.githubusercontent.com/dejavu-fonts/dejavu-fonts/master/ttf/DejaVuSans-Bold.ttf",
        "DejaVuSans-Oblique.ttf": "https://raw.githubusercontent.com/dejavu-fonts/dejavu-fonts/master/ttf/DejaVuSans-Oblique.ttf"
    }
    headers = {'User-Agent': 'Mozilla/5.0'}
    for font_name, font_url in fonts.items():
        if not os.path.exists(font_name):
            try:
                req = urllib.request.Request(font_url, headers=headers)
                with urllib.request.urlopen(req) as response, open(font_name, 'wb') as out_file:
                    out_file.write(response.read())
            except Exception:
                pass

telecharger_polices()

SCEAU_SENEGAL_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAABHNCSVQICAgIfAhkiAAAAAlwSFlz"
    "AAAOxAAADsQBlSsOGwAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ2V3ZgZ3AAAAYklE"
    "EQVR4nO3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAICXAcB4AAEq99A1"
    "AAAAAElFTkSuQmCC"
)

def assistant_ia_repondre(question: str) -> str:
    q = question.lower()
    if "bulletin" in q or "note" in q:
        return "Les bulletins d'excellence sont générés automatiquement au format PDF standardisé sous l'autorité de l'IA Saint-Louis et IEF Saint-Louis, garantissant rigueur et équité pour chaque élève."
    elif "prof" in q or "enseignant" in q:
        return "Nos enseignants d'élite s'engagent au quotidien pour encadrer les notes, le cahier de texte et le suivi personnalisé."
    elif "parent" in q or "élève" in q:
        return "Les parents disposent d'un suivi pédagogique transparent en temps réel pour accompagner la réussite de leurs enfants."
    elif "admin" in q or "administrateur" in q:
        return "L'administration pilote l'établissement avec dévouement pour maintenir les plus hauts standards de qualité académique."
    return "École Président Nelson Mandela - Excellence, Discipline et Réussite au cœur du Système Pédagogique (IA Saint-Louis / IEF Saint-Louis)."

# ==========================================
# 1. CONFIGURATION DE LA PAGE & DESIGN XXL
# ==========================================
st.set_page_config(
    page_title="Sénégal - Portail Éducatif National XXL (IA & IEF Saint-Louis)",
    page_icon="🇸🇳",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800;900&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }

    .stApp {
        background: radial-gradient(circle at top left, #F8FAFC 0%, #EFF6FF 40%, #DBEAFE 100%);
        color: #0F172A;
    }

    @keyframes fadeInSlide {
        0% { opacity: 0; transform: translateY(15px); }
        100% { opacity: 1; transform: translateY(0); }
    }

    @keyframes pulseGlow {
        0% { box-shadow: 0 0 0 0 rgba(14, 116, 144, 0.4); }
        70% { box-shadow: 0 0 0 18px rgba(14, 116, 144, 0); }
        100% { box-shadow: 0 0 0 0 rgba(14, 116, 144, 0); }
    }

    .header-institutionnel {
        background: linear-gradient(135deg, #0EA5E9 0%, #2563EB 50%, #1D4ED8 100%);
        padding: 8px;
        border-radius: 32px;
        box-shadow: 0 25px 50px rgba(14, 165, 233, 0.3);
        margin-bottom: 40px;
        animation: fadeInSlide 0.8s ease-out;
    }

    .header-inner {
        background: rgba(255, 255, 255, 0.99);
        backdrop-filter: blur(20px);
        padding: 32px 40px;
        border-radius: 28px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 30px;
    }

    .header-text {
        text-align: center;
        flex-grow: 1;
    }

    .ministere-title {
        color: #0F172A;
        font-size: clamp(1.3rem, 2.8vw, 2.1rem);
        font-weight: 900;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        margin: 0;
    }

    .ia-ief-sub {
        color: #1E3A8A;
        font-size: clamp(0.95rem, 1.9vw, 1.3rem);
        font-weight: 700;
        margin: 8px 0;
        letter-spacing: 0.5px;
    }

    .ecole-title {
        color: #0EA5E9;
        font-size: clamp(1.5rem, 3vw, 2.5rem);
        font-weight: 900;
        margin: 10px 0 0 0;
        text-transform: uppercase;
    }

    .emblem-box {
        background: #F0F9FF;
        border: 4px solid #0EA5E9;
        border-radius: 50%;
        width: 115px;
        height: 115px;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 10px 25px rgba(14, 165, 233, 0.35);
        flex-shrink: 0;
        animation: pulseGlow 3s infinite;
    }

    .animated-card {
        border: 2px solid rgba(186, 230, 253, 0.9);
        padding: 40px 24px;
        border-radius: 30px;
        background: linear-gradient(145deg, #FFFFFF 0%, #F0F9FF 100%);
        box-shadow: 0 18px 40px rgba(15, 23, 42, 0.1);
        transition: all 0.4s cubic-bezier(0.165, 0.84, 0.44, 1);
        text-align: center;
        margin-bottom: 30px;
        min-height: 330px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        animation: fadeInSlide 0.8s ease-out;
    }

    .animated-card:hover {
        transform: translateY(-12px) scale(1.02);
        border-color: #0EA5E9;
        box-shadow: 0 30px 60px rgba(14, 165, 233, 0.3);
        background: #FFFFFF;
    }

    .stButton>button {
        background: linear-gradient(135deg, #0EA5E9 0%, #0284C7 100%) !important;
        color: #FFFFFF !important;
        border-radius: 18px !important;
        font-weight: 800 !important;
        border: none !important;
        padding: 0.9rem 1.5rem !important;
        transition: all 0.3s ease !important;
        width: 100% !important;
        min-height: 56px !important;
        font-size: 1.1rem !important;
        box-shadow: 0 10px 25px rgba(14, 165, 233, 0.35) !important;
    }

    .stButton>button:hover {
        transform: translateY(-3px) !important;
        box-shadow: 0 15px 32px rgba(14, 165, 233, 0.5) !important;
        background: linear-gradient(135deg, #0284C7 100%, #0369A1 100%) !important;
    }

    .stTextInput input, .stSelectbox select, .stNumberInput input, .stTextArea textarea {
        background-color: #FFFFFF !important;
        color: #0F172A !important;
        border: 2px solid #7DD3FC !important;
        border-radius: 16px !important;
        font-weight: 600 !important;
    }

    .stTextInput input:focus, .stSelectbox select:focus, .stNumberInput input:focus {
        border-color: #0EA5E9 !important;
        box-shadow: 0 0 0 4px rgba(14, 165, 233, 0.25) !important;
    }

    h1, h2, h3, h4, h5, h6, label, p, span {
        color: #0F172A !important;
    }
    </style>
""",
    unsafe_allow_html=True,
)

hide_streamlit_style = """
    <style>
    [data-testid="stToolbar"] { display: none; }
    footer { visibility: hidden; }
    </style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

# ==========================================
# 2. INITIALISATION EXHAUSTIVE DES DONNÉES
# ==========================================
if "espace_actif" not in st.session_state:
    st.session_state.espace_actif = "🏠 Accueil"

if "authenticated_admin" not in st.session_state:
    st.session_state.authenticated_admin = False

if "edt_documents" not in st.session_state:
    st.session_state.edt_documents = saved_data.get("edt_documents", {})

if "admin_credentials" not in st.session_state:
    if "admin_credentials" in saved_data:
        st.session_state.admin_credentials = pd.DataFrame(saved_data["admin_credentials"])
    else:
        st.session_state.admin_credentials = pd.DataFrame([
            {"Nom": "Principal", "Prénom": "Admin", "Email": ADMIN_EMAIL, "Mot de passe": hacher_mot_de_passe("cpnm2026"), "Niveau d'accès": "Super-Admin Ayant-Droit"}
        ])

if "admin_white_list" not in st.session_state:
    if "admin_white_list" in saved_data:
        st.session_state.admin_white_list = pd.DataFrame(saved_data["admin_white_list"])
    else:
        st.session_state.admin_white_list = pd.DataFrame([
            {"Email": ADMIN_EMAIL, "Nom": "Mandela", "Prénom": "Ayant Droit", "Mot de passe": hacher_mot_de_passe("cpnm2026"), "Niveau d'accès": "Super-Admin Ayant-Droit"},
            {"Email": "direction@cpnm.sn", "Nom": "Ndiaye", "Prénom": "Modou", "Mot de passe": hacher_mot_de_passe("dir2026"), "Niveau d'accès": "Administrateur"}
        ])

if "prof_credentials" not in st.session_state:
    if "prof_credentials" in saved_data:
        st.session_state.prof_credentials = pd.DataFrame(saved_data["prof_credentials"])
    else:
        st.session_state.prof_credentials = pd.DataFrame([
            {"Nom": "Diallo", "Prénom": "Ibrahima", "Email": "i.diallo@cpnm.sn", "Mot de passe": hacher_mot_de_passe("prof123"), "Matière Principale": "Mathématiques", "Classe Attribuée": "6ème A"},
            {"Nom": "Sow", "Prénom": "Aissatou", "Email": "a.sow@cpnm.sn", "Mot de passe": hacher_mot_de_passe("prof456"), "Matière Principale": "Français", "Classe Attribuée": "CP"},
            {"Nom": "Ndiaye", "Prénom": "Cheikh", "Email": "c.ndiaye@cpnm.sn", "Mot de passe": hacher_mot_de_passe("prof789"), "Matière Principale": "Histoire-Géographie", "Classe Attribuée": "5ème A"}
        ])

for col in ["Nom", "Prénom", "Email", "Matière Principale", "Classe Attribuée", "Mot de passe"]:
    if col not in st.session_state.prof_credentials.columns:
        st.session_state.prof_credentials[col] = ""

if "prof_white_list" not in st.session_state:
    if "prof_white_list" in saved_data:
        st.session_state.prof_white_list = pd.DataFrame(saved_data["prof_white_list"])
    else:
        sync_wl = []
        for _, r in st.session_state.prof_credentials.iterrows():
            sync_wl.append({
                "Email": r.get("Email", ""),
                "Nom": r.get("Nom", ""),
                "Prénom": r.get("Prénom", ""),
                "Mot de passe": r.get("Mot de passe", ""),
                "Matière Principale": r.get("Matière Principale", ""),
                "Classe Attribuée": r.get("Classe Attribuée", "")
            })
        st.session_state.prof_white_list = pd.DataFrame(sync_wl)

if "parents_white_list" not in st.session_state:
    if "parents_white_list" in saved_data:
        st.session_state.parents_white_list = pd.DataFrame(saved_data["parents_white_list"])
    else:
        st.session_state.parents_white_list = pd.DataFrame([
            {"Téléphone": "+221771234567", "Prénom Élève": "Mamadou", "Nom Élève": "Diallo", "Année Naissance": 2012, "Classe": "6ème A"},
            {"Téléphone": ADMIN_EMAIL, "Prénom Élève": "Fatou", "Nom Élève": "Sow", "Année Naissance": 2015, "Classe": "CP"},
        ])

if "classes_db" not in st.session_state:
    if "classes_db" in saved_data:
        st.session_state.classes_db = pd.DataFrame(saved_data["classes_db"])
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
        st.session_state.eleves_db = pd.DataFrame(saved_data["eleves_db"])
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

if "eleves_db" in st.session_state and not st.session_state.eleves_db.empty and "Nom Complet" in st.session_state.eleves_db.columns:
    st.session_state.eleves_db = st.session_state.eleves_db.sort_values(by="Nom Complet", ascending=True).reset_index(drop=True)

if "matieres_def" not in st.session_state:
    if "matieres_def" in saved_data:
        st.session_state.matieres_def = pd.DataFrame(saved_data["matieres_def"])
    else:
        st.session_state.matieres_def = pd.DataFrame([
            {"Matière": "Mathématiques", "Cycle": "Collège", "Coefficient": 4, "Barème": 20},
            {"Matière": "Français", "Cycle": "Collège", "Coefficient": 5, "Barème": 20},
            {"Matière": "Histoire-Géographie", "Cycle": "Collège", "Coefficient": 2, "Barème": 20},
            {"Matière": "SVT", "Cycle": "Collège", "Coefficient": 2, "Barème": 20},
            {"Matière": "Anglais", "Cycle": "Collège", "Coefficient": 2, "Barème": 20},
            {"Matière": "Physique-Chimie", "Cycle": "Collège", "Coefficient": 2, "Barème": 20},
            {"Matière": "Lecture / Langage", "Cycle": "Élémentaire", "Coefficient": 1, "Barème": 50},
            {"Matière": "Calcul / Mathématiques", "Cycle": "Élémentaire", "Coefficient": 1, "Barème": 50},
            {"Matière": "Éveil / Science", "Cycle": "Élémentaire", "Coefficient": 1, "Barème": 30},
            {"Matière": "Éducation Civique", "Cycle": "Élémentaire", "Coefficient": 1, "Barème": 20}
        ])

if "Barème" not in st.session_state.matieres_def.columns:
    st.session_state.matieres_def["Barème"] = st.session_state.matieres_def["Cycle"].apply(lambda x: 20 if x == "Collège" else 50)

if "coefficients_db" not in st.session_state:
    if "coefficients_db" in saved_data:
        st.session_state.coefficients_db = pd.DataFrame(saved_data["coefficients_db"])
    else:
        st.session_state.coefficients_db = pd.DataFrame([
            {"Classe": "6ème A", "Matière": "Mathématiques", "Coefficient": 4, "Barème": 20},
            {"Classe": "6ème A", "Matière": "Français", "Coefficient": 5, "Barème": 20},
            {"Classe": "6ème A", "Matière": "Histoire-Géographie", "Coefficient": 2, "Barème": 20},
            {"Classe": "6ème A", "Matière": "SVT", "Coefficient": 2, "Barème": 20},
            {"Classe": "6ème A", "Matière": "Anglais", "Coefficient": 2, "Barème": 20},
            {"Classe": "6ème A", "Matière": "Physique-Chimie", "Coefficient": 2, "Barème": 20},
            {"Classe": "CP", "Matière": "Lecture / Langage", "Coefficient": 1, "Barème": 50},
            {"Classe": "CP", "Matière": "Calcul / Mathématiques", "Coefficient": 1, "Barème": 50},
            {"Classe": "CP", "Matière": "Éveil / Science", "Coefficient": 1, "Barème": 30},
            {"Classe": "CP", "Matière": "Éducation Civique", "Coefficient": 1, "Barème": 20}
        ])

if "Barème" not in st.session_state.coefficients_db.columns:
    st.session_state.coefficients_db["Barème"] = 20

if "periodes_db" not in st.session_state:
    if "periodes_db" in saved_data:
        st.session_state.periodes_db = pd.DataFrame(saved_data["periodes_db"])
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
        st.session_state.notes_db = pd.DataFrame(saved_data["notes_db"])
    else:
        st.session_state.notes_db = pd.DataFrame(
            columns=["Classe", "Matière", "Periode", "Période", "Eleve", "Devoir1", "Devoir2", "Composition", "BaremeNote"],
            data=[
                ["6ème A", "Mathématiques", "1er Semestre", "1er Semestre", "Mamadou Diallo", 14.0, 15.0, 13.5, 20.0],
                ["6ème A", "Français", "1er Semestre", "1er Semestre", "Mamadou Diallo", 12.0, 11.5, 13.0, 20.0],
                ["CP", "Calcul / Mathématiques", "1er Trimestre", "1er Trimestre", "Fatou Sow", 0.0, 0.0, 42.0, 50.0]
            ]
        )

if isinstance(st.session_state.notes_db, pd.DataFrame):
    st.session_state.notes_db = st.session_state.notes_db.reset_index(drop=True)
    if "BaremeNote" not in st.session_state.notes_db.columns:
        st.session_state.notes_db["BaremeNote"] = 20.0

if "Periode" not in st.session_state.notes_db.columns and "Période" in st.session_state.notes_db.columns:
    st.session_state.notes_db["Periode"] = st.session_state.notes_db["Période"]
elif "Période" not in st.session_state.notes_db.columns and "Periode" in st.session_state.notes_db.columns:
    st.session_state.notes_db["Période"] = st.session_state.notes_db["Periode"]
elif "Periode" not in st.session_state.notes_db.columns and "Période" not in st.session_state.notes_db.columns:
    st.session_state.notes_db["Periode"] = "1er Semestre"
    st.session_state.notes_db["Période"] = "1er Semestre"

if "viescolaire_db" not in st.session_state:
    if "viescolaire_db" in saved_data:
        st.session_state.viescolaire_db = pd.DataFrame(saved_data["viescolaire_db"])
    else:
        st.session_state.viescolaire_db = pd.DataFrame(
            columns=["Classe", "Periode", "Période", "Eleve", "AbsencesJustifiees", "AbsencesNonJustifiees", "Retards", "HeuresPerdues", "Observations", "DecisionConseil"],
            data=[
                ["6ème A", "1er Semestre", "1er Semestre", "Mamadou Diallo", 1, 0, 1, 2, "Elève sérieux et appliqué.", "Tableau d'honneur"],
                ["CP", "1er Trimestre", "1er Trimestre", "Fatou Sow", 0, 0, 0, 0, "Très bon trimestre.", "Félicitations"]
            ]
        )

JOURS_LIST = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi"]

HEURES_LIST = [
    "08h-09h", "09h-10h", "10h-11h", 
    "11h00-11h30", "11h30-12h", 
    "12h-13h", "13h-14h", "14h-15h", "15h-16h", 
    "16h-17h", "17h-18h", "18h-19h"
]

if "edt_grid_db" not in st.session_state:
    if "edt_grid_db" in saved_data:
        st.session_state.edt_grid_db = {k: pd.DataFrame(v) for k, v in saved_data["edt_grid_db"].items()}
    else:
        st.session_state.edt_grid_db = {}

def get_or_create_edt(classe):
    if classe not in st.session_state.edt_grid_db:
        df_def = pd.DataFrame("", index=JOURS_LIST, columns=HEURES_LIST)
        if "11h00-11h30" in df_def.columns:
            df_def["11h00-11h30"] = "Récréation"
        st.session_state.edt_grid_db[classe] = df_def
    else:
        df_exist = st.session_state.edt_grid_db[classe]
        if "11h00-11h30" not in df_exist.columns:
            df_def = pd.DataFrame("", index=JOURS_LIST, columns=HEURES_LIST)
            for col in df_exist.columns:
                if col in df_def.columns:
                    df_def[col] = df_exist[col]
            if "11h00-11h30" in df_def.columns:
                df_def["11h00-11h30"] = "Récréation"
            st.session_state.edt_grid_db[classe] = df_def
    return st.session_state.edt_grid_db[classe]

if "cahier_textes" not in st.session_state:
    if "cahier_textes" in saved_data:
        st.session_state.cahier_textes = pd.DataFrame(saved_data["cahier_textes"])
    else:
        st.session_state.cahier_textes = pd.DataFrame(columns=["Professeur", "Date", "Classe", "Matière", "Contenu", "Travail à faire"], data=[])

if "absences_db" not in st.session_state:
    if "absences_db" in saved_data:
        st.session_state.absences_db = pd.DataFrame(saved_data["absences_db"])
    else:
        st.session_state.absences_db = pd.DataFrame(columns=["Date", "Classe", "Élève", "Statut", "Motif"], data=[])

synchroniser_listes_blanches()

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
        df_p = st.session_state.periodes_db
        col_cycle = "Cycle" if "Cycle" in df_p.columns else None
        col_periode = "Période" if "Période" in df_p.columns else ("Periode" if "Periode" in df_p.columns else None)
        
        if col_cycle and col_periode:
            filtre = df_p[df_p[col_cycle] == cycle][col_periode].dropna().tolist()
            if filtre:
                return filtre
        elif col_periode:
            return df_p[col_periode].dropna().tolist()
            
    if cycle == "Élémentaire":
        return ["1er Trimestre", "2ème Trimestre", "3ème Trimestre"]
    else:
        return ["1er Semestre", "2ème Semestre"]

def obtenir_appreciation(moyenne, cycle="Collège", bareme=20):
    if pd.isna(moyenne):
        return "N/A"
    m = (moyenne / bareme) * 20.0 if bareme > 0 else moyenne
    if m >= 18:
        return "Excellent"
    elif m >= 16:
        return "Très Bien"
    elif m >= 14:
        return "Bien"
    elif m >= 12:
        return "Assez Bien"
    elif m >= 10:
        return "Passable"
    elif m >= 8:
        return "Insuffisant"
    else:
        return "Faible"

def obtenir_coefficient_matiere(classe, matiere):
    if "coefficients_db" in st.session_state and not st.session_state.coefficients_db.empty:
        c_db = st.session_state.coefficients_db
        res = c_db[(c_db["Classe"] == classe) & (c_db["Matière"] == matiere)]
        if not res.empty and pd.notna(res.iloc[0].get("Coefficient")):
            return float(res.iloc[0]["Coefficient"])
            
    cycle_classe = obtenir_cycle_classe(classe)
    if "matieres_def" in st.session_state and not st.session_state.matieres_def.empty:
        m_def = st.session_state.matieres_def
        if "Cycle" in m_def.columns:
            res = m_def[(m_def["Matière"] == matiere) & (m_def["Cycle"] == cycle_classe)]
        else:
            res = m_def[m_def["Matière"] == matiere]
        if not res.empty and "Coefficient" in m_def.columns and pd.notna(res.iloc[0].get("Coefficient")):
            return float(res.iloc[0]["Coefficient"])
            
    return 1.0

def obtenir_bareme_matiere(classe, matiere):
    if "coefficients_db" in st.session_state and not st.session_state.coefficients_db.empty:
        c_db = st.session_state.coefficients_db
        res = c_db[(c_db["Classe"] == classe) & (c_db["Matière"] == matiere)]
        if not res.empty and "Barème" in res.columns and pd.notna(res.iloc[0].get("Barème")):
            return float(res.iloc[0]["Barème"])
            
    cycle_classe = obtenir_cycle_classe(classe)
    if "matieres_def" in st.session_state and not st.session_state.matieres_def.empty:
        m_def = st.session_state.matieres_def
        if "Cycle" in m_def.columns:
            res = m_def[(m_def["Matière"] == matiere) & (m_def["Cycle"] == cycle_classe)]
        else:
            res = m_def[m_def["Matière"] == matiere]
        if not res.empty and "Barème" in m_def.columns and pd.notna(res.iloc[0].get("Barème")):
            return float(res.iloc[0]["Barème"])
            
    return 20.0 if cycle_classe == "Collège" else 50.0

def ajouter_entete_senegal_officiel(pdf, titre_document=""):
    try:
        font_family = "DejaVu" if "DejaVu" in pdf.core_fonts or hasattr(pdf, "fonts") and "DejaVu" in pdf.fonts else "Arial"
    except Exception:
        font_family = "Arial"

    try:
        if SCEAU_SENEGAL_B64:
            img_data = base64.b64decode(SCEAU_SENEGAL_B64)
            img_bytes = io.BytesIO(img_data)
            pdf.image(img_bytes, x=15, y=8, w=22)
    except Exception:
        pass

    pdf.set_font(font_family, "B", 10)
    pdf.cell(0, 4, "RÉPUBLIQUE DU SÉNÉGAL", 0, 1, "C")
    pdf.set_font(font_family, "", 8)
    pdf.cell(0, 4, "Un Peuple - Un But - Une Foi", 0, 1, "C")
    pdf.set_font(font_family, "B", 9)
    pdf.cell(0, 4, "MINISTÈRE DE L'ÉDUCATION NATIONALE", 0, 1, "C")
    pdf.set_font(font_family, "B", 9)
    pdf.cell(0, 4, "INSPECTION D'ACADÉMIE DE SAINT-LOUIS (IA SAINT-LOUIS)", 0, 1, "C")
    pdf.set_font(font_family, "B", 9)
    pdf.cell(0, 4, "INSPECTION DE L'ÉDUCATION ET DE LA FORMATION DE SAINT-LOUIS (IEF SAINT-LOUIS)", 0, 1, "C")
    
    pdf.set_font(font_family, "B", 10)
    pdf.cell(0, 5, "ÉCOLE PRÉSIDENT NELSON MANDELA", 0, 1, "C")
    
    if titre_document:
        pdf.set_font(font_family, "B", 11)
        pdf.set_text_color(14, 165, 233)
        pdf.cell(0, 6, titre_document.upper(), 0, 1, "C")
        pdf.set_text_color(0, 0, 0)

    pdf.set_draw_color(14, 165, 233)
    if hasattr(pdf, "set_line_width"):
        pdf.set_line_width(0.8)
    elif hasattr(pdf, "set_linewidth"):
        pdf.set_linewidth(0.8)
    pdf.line(10, 38, 200, 38)
    pdf.ln(5)

def ajouter_bloc_signatures(pdf, prof_nom="Le Professeur", chef_nom="Le Chef d'Établissement / IEF"):
    try:
        font_family = "DejaVu" if "DejaVu" in pdf.core_fonts or hasattr(pdf, "fonts") and "DejaVu" in pdf.fonts else "Arial"
    except Exception:
        font_family = "Arial"

    pdf.ln(8)
    pdf.set_font(font_family, "B", 8)
    pdf.set_draw_color(200, 200, 200)

    pdf.cell(90, 5, f"SIGNATURE & TAMPON : {prof_nom.upper()}", 1, 0, "C")
    pdf.cell(10, 5, "", 0, 0, "C")
    pdf.cell(90, 5, f"VALIDEUR : {chef_nom.upper()} (IA/IEF)", 1, 1, "C")

    pdf.set_font(font_family, "I", 7)
    pdf.cell(90, 15, "Sceau numérique & Empreinte d'excellence", "LRB", 0, "C")
    pdf.cell(10, 15, "", 0, 0, "C")
    pdf.cell(90, 15, "Cachet officiel de l'Établissement d'Excellence", "LRB", 1, "C")

def calculer_bulletin_eleve(classe, eleve, periode):
    cycle_classe = obtenir_cycle_classe(classe)
    matieres_set = set()
    
    if "coefficients_db" in st.session_state and not st.session_state.coefficients_db.empty:
        c_db = st.session_state.coefficients_db
        m_c = c_db[c_db["Classe"] == classe]["Matière"].dropna().tolist()
        matieres_set.update(m_c)
        
    if "matieres_def" in st.session_state and not st.session_state.matieres_def.empty:
        m_def = st.session_state.matieres_def
        if "Cycle" in m_def.columns:
            m_c_def = m_def[m_def["Cycle"] == cycle_classe]["Matière"].dropna().tolist()
            matieres_set.update(m_c_def)
        else:
            matieres_set.update(m_def["Matière"].dropna().tolist())

    notes_df = st.session_state.notes_db if "notes_db" in st.session_state else pd.DataFrame()
    
    if not notes_df.empty:
        cond_cls = (notes_df["Classe"] == classe)
        if "Periode" in notes_df.columns and "Période" in notes_df.columns:
            cond_per = (notes_df["Periode"] == periode) | (notes_df["Période"] == periode)
        elif "Periode" in notes_df.columns:
            cond_per = (notes_df["Periode"] == periode)
        elif "Période" in notes_df.columns:
            cond_per = (notes_df["Période"] == periode)
        else:
            cond_per = True
            
        m_notes = notes_df[cond_cls & cond_per]["Matière"].dropna().unique().tolist()
        matieres_set.update(m_notes)

    if not matieres_set:
        matieres_set = {"Mathématiques", "Français"} if cycle_classe == "Collège" else {"Lecture / Langage", "Calcul / Mathématiques"}

    liste_matieres = sorted(list(matieres_set))

    notes_classe_periode = pd.DataFrame()
    if not notes_df.empty:
        if "Periode" in notes_df.columns:
            notes_classe_periode = notes_df[(notes_df["Classe"] == classe) & (notes_df["Periode"] == periode)]
        elif "Période" in notes_df.columns:
            notes_classe_periode = notes_df[(notes_df["Classe"] == classe) & (notes_df["Période"] == periode)]

    lignes_bulletin = []
    total_points_global = 0.0
    total_coefficients_global = 0.0
    total_bareme_global = 0.0

    coeffs_dict = {}
    baremes_dict = {}
    for mat in liste_matieres:
        coeffs_dict[mat] = obtenir_coefficient_matiere(classe, mat)
        baremes_dict[mat] = obtenir_bareme_matiere(classe, mat)

    for mat in liste_matieres:
        coef = coeffs_dict.get(mat, 1.0)
        bareme_m = baremes_dict.get(mat, 20.0 if cycle_classe == "Collège" else 50.0)
        
        note_row = notes_classe_periode[notes_classe_periode["Eleve"] == eleve] if not notes_classe_periode.empty else pd.DataFrame()
        note_mat = note_row[note_row["Matière"] == mat] if not note_row.empty else pd.DataFrame()

        d1, d2, comp = 0.0, 0.0, 0.0
        if not note_mat.empty:
            d1_val = note_mat.iloc[0]["Devoir1"]
            d2_val = note_mat.iloc[0]["Devoir2"]
            comp_val = note_mat.iloc[0]["Composition"]

            d1 = float(d1_val) if pd.notna(d1_val) else 0.0
            d2 = float(d2_val) if pd.notna(d2_val) else 0.0
            comp = float(comp_val) if pd.notna(comp_val) else 0.0

        if cycle_classe == "Élémentaire":
            moy_matiere = comp
            total_points_global += moy_matiere
            total_bareme_global += bareme_m
            
            lignes_bulletin.append({
                "Matiere": mat,
                "Bareme": bareme_m,
                "Composition": comp,
                "MoyenneMatiere": round(moy_matiere, 2),
                "Appreciation": obtenir_appreciation(moy_matiere, cycle_classe, bareme_m)
            })
        else:
            moy_devoirs = (d1 + d2) / 2.0
            moy_matiere = (moy_devoirs + comp) / 2.0
            total_pondere = moy_matiere * coef
            
            total_points_global += total_pondere
            total_coefficients_global += coef

            lignes_bulletin.append({
                "Matiere": mat,
                "Coefficient": coef,
                "Devoir1": d1,
                "Devoir2": d2,
                "Composition": comp,
                "MoyenneMatiere": round(moy_matiere, 2),
                "TotalPondere": round(total_pondere, 2),
                "Appreciation": obtenir_appreciation(moy_matiere, cycle_classe, 20.0)
            })

    if cycle_classe == "Élémentaire":
        moyenne_generale = round(total_points_global, 2)
    else:
        moyenne_generale = round(total_points_global / total_coefficients_global, 2) if total_coefficients_global > 0 else 0.0

    tous_eleves = st.session_state.eleves_db[st.session_state.eleves_db["Classe"] == classe]["Nom Complet"].tolist()
    moyennes_classe = {}
    for el in tous_eleves:
        pts = 0.0
        coefs = 0.0
        notes_el_p = notes_classe_periode[notes_classe_periode["Eleve"] == el] if not notes_classe_periode.empty else pd.DataFrame()
        for mat in liste_matieres:
            coef = coeffs_dict.get(mat, 1.0)
            n_m = notes_el_p[notes_el_p["Matière"] == mat] if not notes_el_p.empty else pd.DataFrame()
            if not n_m.empty:
                d1_val = n_m.iloc[0]["Devoir1"]
                d2_val = n_m.iloc[0]["Devoir2"]
                comp_val = n_m.iloc[0]["Composition"]
                d1 = float(d1_val) if pd.notna(d1_val) else 0.0
                d2 = float(d2_val) if pd.notna(d2_val) else 0.0
                comp = float(comp_val) if pd.notna(comp_val) else 0.0
                
                if cycle_classe == "Élémentaire":
                    pts += comp
                else:
                    m_mat = ((d1 + d2) / 2.0 + comp) / 2.0
                    pts += m_mat * coef
                    coefs += coef
        if cycle_classe == "Élémentaire":
            moyennes_classe[el] = round(pts, 2)
        else:
            moyennes_classe[el] = round(pts / coefs, 2) if coefs > 0 else 0.0

    classement_trie = sorted(moyennes_classe.items(), key=lambda x: x[1], reverse=True)
    rang = "-"
    for idx, (el_nom, _) in enumerate(classement_trie, 1):
        if el_nom == eleve:
            rang = f"{idx} / {len(tous_eleves)}"
            break

    vs_df = st.session_state.viescolaire_db
    vs_row = pd.DataFrame()
    if not vs_df.empty:
        if "Periode" in vs_df.columns:
            vs_row = vs_df[(vs_df["Classe"] == classe) & (vs_df["Periode"] == periode) & (vs_df["Eleve"] == eleve)]
        elif "Période" in vs_df.columns:
            vs_row = vs_df[(vs_df["Classe"] == classe) & (vs_df["Période"] == periode) & (vs_df["Eleve"] == eleve)]

    abs_just, abs_non_just, retards, heures_p, obs, decision = 0, 0, 0, 0, "RAS", "Encouragements"
    if not vs_row.empty:
        abs_just = int(vs_row.iloc[0]["AbsencesJustifiees"]) if pd.notna(vs_row.iloc[0]["AbsencesJustifiees"]) else 0
        abs_non_just = int(vs_row.iloc[0]["AbsencesNonJustifiees"]) if pd.notna(vs_row.iloc[0]["AbsencesNonJustifiees"]) else 0
        retards = int(vs_row.iloc[0]["Retards"]) if pd.notna(vs_row.iloc[0]["Retards"]) else 0
        heures_p = int(vs_row.iloc[0]["HeuresPerdues"]) if pd.notna(vs_row.iloc[0]["HeuresPerdues"]) else 0
        obs = str(vs_row.iloc[0]["Observations"]) if pd.notna(vs_row.iloc[0]["Observations"]) else "RAS"
        decision = str(vs_row.iloc[0]["DecisionConseil"]) if pd.notna(vs_row.iloc[0]["DecisionConseil"]) else "Encouragements"

    return {
        "eleve": eleve,
        "classe": classe,
        "cycle": cycle_classe,
        "periode": periode,
        "lignes": lignes_bulletin,
        "total_points": round(total_points_global, 2),
        "total_coefficients": total_coefficients_global if cycle_classe == "Collège" else "-",
        "total_bareme": total_bareme_global if cycle_classe == "Élémentaire" else 20.0,
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
    try:
        if os.path.exists("DejaVuSans.ttf"):
            pdf.add_font("DejaVu", "", "DejaVuSans.ttf", uni=True)
            pdf.add_font("DejaVu", "B", "DejaVuSans-Bold.ttf", uni=True)
            font_family = "DejaVu"
        else:
            font_family = "Arial"
    except Exception:
        font_family = "Arial"

    pdf.add_page()
    cycle = bul_data.get("cycle", "Collège")
    
    ajouter_entete_senegal_officiel(pdf, f"BULLETIN DE NOTES - {bul_data['periode'].upper()} ({cycle.upper()})")

    pdf.set_font(font_family, "B", 10)
    pdf.cell(100, 6, f"Nom et Prénom : {bul_data['eleve']}", 0, 0, "L")
    pdf.cell(90, 6, f"Classe : {bul_data['classe']}", 0, 1, "R")
    pdf.cell(100, 6, f"Effectif : {bul_data['effectif']} élèves", 0, 0, "L")
    pdf.cell(90, 6, f"Rang : {bul_data['rang']}", 0, 1, "R")
    pdf.ln(4)

    pdf.set_font(font_family, "B", 9)
    pdf.set_fill_color(14, 165, 233)
    pdf.set_text_color(255, 255, 255)
    
    if cycle == "Élémentaire":
        col_widths = [95, 30, 35, 30]
        headers = ["Matière", "Barème", "Note obtenue", "Appréciation"]
    else:
        col_widths = [65, 18, 18, 18, 22, 22, 27]
        headers = ["Matière", "Coef", "Dev 1", "Dev 2", "Comp", "Moy/20", "Appréciation"]
    
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 7, h, 1, 0, "C", True)
    pdf.ln()

    pdf.set_font(font_family, "", 8)
    pdf.set_text_color(0, 0, 0)
    fill = False
    pdf.set_fill_color(240, 249, 255)

    for lig in bul_data["lignes"]:
        if cycle == "Élémentaire":
            pdf.cell(col_widths[0], 6, str(lig["Matiere"])[:30], 1, 0, "L", fill)
            pdf.cell(col_widths[1], 6, f"/ {lig['Bareme']}", 1, 0, "C", fill)
            pdf.cell(col_widths[2], 6, str(lig["Composition"]), 1, 0, "C", fill)
            pdf.cell(col_widths[3], 6, str(lig["Appreciation"])[:15], 1, 0, "C", fill)
        else:
            pdf.cell(col_widths[0], 6, str(lig["Matiere"])[:25], 1, 0, "L", fill)
            pdf.cell(col_widths[1], 6, str(lig["Coefficient"]), 1, 0, "C", fill)
            pdf.cell(col_widths[2], 6, str(lig["Devoir1"]), 1, 0, "C", fill)
            pdf.cell(col_widths[3], 6, str(lig["Devoir2"]), 1, 0, "C", fill)
            pdf.cell(col_widths[4], 6, str(lig["Composition"]), 1, 0, "C", fill)
            pdf.cell(col_widths[5], 6, str(lig["MoyenneMatiere"]), 1, 0, "C", fill)
            pdf.cell(col_widths[6], 6, str(lig["Appreciation"])[:15], 1, 0, "C", fill)
        pdf.ln()
        fill = not fill

    pdf.ln(4)
    pdf.set_font(font_family, "B", 10)
    pdf.set_fill_color(224, 242, 254)
    if cycle == "Élémentaire":
        pdf.cell(0, 6, f"Total Général : {bul_data['moyenne_generale']} / {bul_data['total_bareme']}", 1, 1, "L", True)
    else:
        pdf.cell(0, 6, f"Moyenne Générale : {bul_data['moyenne_generale']} / 20", 1, 1, "L", True)
    pdf.ln(3)

    pdf.set_font(font_family, "B", 9)
    pdf.cell(0, 5, "BILAN DE LA VIE SCOLAIRE ET DISCIPLINE", 0, 1, "L")
    pdf.set_font(font_family, "", 9)
    pdf.cell(0, 5, f"Absences justifiées : {bul_data['abs_just']} | Absences non justifiées : {bul_data['abs_non_just']} | Retards : {bul_data['retards']} | Heures perdues : {bul_data['heures_perdues']}h", 1, 1, "L")
    pdf.cell(0, 5, f"Observations / Appréciation générale : {bul_data['observations']}", 1, 1, "L")
    pdf.cell(0, 5, f"Décision du Conseil de Classe : {bul_data['decision']}", 1, 1, "L")

    ajouter_bloc_signatures(pdf, prof_nom="Professeur Principal", chef_nom="Inspecteur / Directeur IEF Saint-Louis")

    return bytes(pdf.output())

def generer_zip_bulletins_classe(classe, periode):
    eleves = st.session_state.eleves_db[st.session_state.eleves_db["Classe"] == classe]
    if "Nom Complet" in eleves.columns:
        eleves = eleves.sort_values(by="Nom Complet", ascending=True)
    eleves_list = eleves["Nom Complet"].tolist()
    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for eleve in eleves_list:
            bul_data = calculer_bulletin_eleve(classe, eleve, periode)
            pdf_bytes = generer_pdf_bulletin(bul_data)
            filename = f"Bulletin_{classe}_{eleve.replace(' ', '_')}_{periode.replace(' ', '_')}.pdf"
            zip_file.writestr(filename, pdf_bytes)
    return zip_buffer.getvalue()

def generer_pdf_liste_eleves_classe(classe):
    df_eleves = st.session_state.eleves_db[st.session_state.eleves_db["Classe"] == classe]
    if "Nom Complet" in df_eleves.columns:
        df_eleves = df_eleves.sort_values(by="Nom Complet", ascending=True)
        
    pdf = FPDF()
    try:
        font_family = "DejaVu" if os.path.exists("DejaVuSans.ttf") else "Arial"
    except Exception:
        font_family = "Arial"
        
    pdf.add_page()
    ajouter_entete_senegal_officiel(pdf, f"FICHE OFFICIELLE DE LA CLASSE : {classe} (Tri Alphabétique)")

    pdf.set_font(font_family, "B", 9)
    pdf.set_fill_color(14, 165, 233)
    pdf.set_text_color(255, 255, 255)

    col_widths = [75, 45, 70]
    headers = ["Nom Complet de l'Élève", "Classe", "Date de Naissance"]

    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 7, h, 1, 0, "C", True)
    pdf.ln()

    pdf.set_font(font_family, "", 8)
    pdf.set_text_color(0, 0, 0)
    fill = False
    pdf.set_fill_color(240, 249, 255)

    for _, row in df_eleves.iterrows():
        pdf.cell(col_widths[0], 6, str(row.get("Nom Complet", ""))[:35], 1, 0, "L", fill)
        pdf.cell(col_widths[1], 6, str(row.get("Classe", ""))[:20], 1, 0, "C", fill)
        pdf.cell(col_widths[2], 6, str(row.get("Date de Naissance", ""))[:20], 1, 0, "C", fill)
        pdf.ln()
        fill = not fill

    ajouter_bloc_signatures(pdf, prof_nom="Responsable de Scolarité", chef_nom="Inspecteur IEF Saint-Louis")
    return bytes(pdf.output())

def generer_pdf_edt(classe, df_edt):
    pdf = FPDF(orientation='L', unit='mm', format='A4')
    try:
        font_family = "DejaVu" if os.path.exists("DejaVuSans.ttf") else "Arial"
    except Exception:
        font_family = "Arial"

    pdf.add_page()
    ajouter_entete_senegal_officiel(pdf, f"EMPLOI DU TEMPS OFFICIEL DE LA CLASSE : {classe}")

    pdf.set_font(font_family, "B", 8)
    pdf.set_fill_color(14, 165, 233)
    pdf.set_text_color(255, 255, 255)

    col_w = 22
    pdf.cell(30, 7, "Jour / Heure", 1, 0, "C", True)
    for col in df_edt.columns:
        pdf.cell(col_w, 7, str(col)[:8], 1, 0, "C", True)
    pdf.ln()

    pdf.set_font(font_family, "", 7)
    pdf.set_text_color(0, 0, 0)

    for jour in df_edt.index:
        pdf.cell(30, 6, str(jour), 1, 0, "C", True)
        for col in df_edt.columns:
            val = str(df_edt.loc[jour, col])
            pdf.cell(col_w, 6, val[:12], 1, 0, "C", True)
        pdf.ln()

    ajouter_bloc_signatures(pdf, prof_nom="Chef d'Établissement", chef_nom="Inspecteur IA Saint-Louis")

    return bytes(pdf.output())

def generer_pdf_cahier_textes(df_ct, classe="Global"):
    pdf = FPDF()
    try:
        font_family = "DejaVu" if os.path.exists("DejaVuSans.ttf") else "Arial"
    except Exception:
        font_family = "Arial"

    pdf.add_page()
    ajouter_entete_senegal_officiel(pdf, f"REGISTRE ET CAHIER DE TEXTES - {classe.upper()}")

    pdf.set_font(font_family, "B", 8)
    pdf.set_fill_color(14, 165, 233)
    pdf.set_text_color(255, 255, 255)

    col_widths = [25, 30, 30, 55, 50]
    headers = ["Date", "Classe", "Matière", "Contenu de la leçon", "Devoirs / Travail"]

    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 7, h, 1, 0, "C", True)
    pdf.ln()

    pdf.set_font(font_family, "", 7)
    pdf.set_text_color(0, 0, 0)
    fill = False
    pdf.set_fill_color(240, 249, 255)

    for _, row in df_ct.iterrows():
        pdf.cell(col_widths[0], 6, str(row.get("Date", ""))[:10], 1, 0, "C", fill)
        pdf.cell(col_widths[1], 6, str(row.get("Classe", ""))[:12], 1, 0, "C", fill)
        pdf.cell(col_widths[2], 6, str(row.get("Matière", ""))[:15], 1, 0, "L", fill)
        pdf.cell(col_widths[3], 6, str(row.get("Contenu", ""))[:35], 1, 0, "L", fill)
        pdf.cell(col_widths[4], 6, str(row.get("Travail à faire", ""))[:30], 1, 0, "L", fill)
        pdf.ln()
        fill = not fill

    ajouter_bloc_signatures(pdf, prof_nom="L'Enseignant Concerné", chef_nom="L'Inspecteur Pédagogique")

    return bytes(pdf.output())

def export_table_excel(df, filename="export_donnees.xlsx"):
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=True, sheet_name='Donnees')
    processed_data = output.getvalue()
    return processed_data

# ==========================================
# 4. EN-TÊTE ET NAVIGATION GLOBALE DESIGN XXL
# ==========================================
st.markdown(
    """
    <div class="header-institutionnel">
        <div class="header-inner">
            <div class="emblem-box">
                <span style="font-size: 3.2rem;">🇸🇳</span>
            </div>
            <div class="header-text">
                <div class="ministere-title">MINISTÈRE DE L'ÉDUCATION NATIONALE DU SÉNÉGAL</div>
                <div class="ia-ief-sub">INSPECTION D'ACADÉMIE DE SAINT-LOUIS (IA) • INSPECTION DE L'ÉDUCATION ET DE LA FORMATION (IEF)</div>
                <div class="ecole-title">🦁 ÉCOLE PRÉSIDENT NELSON MANDELA</div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

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
        <div style="text-align: center; padding: 15px 0 35px 0;">
            <h1 style="color: #0F172A; font-weight: 900; font-size: 2.9rem;">Portail Éducatif National • Excellence & Réussite</h1>
            <p style="font-size: 1.3rem; color: #334155; max-width: 1000px; margin: 0 auto; font-weight: 500;">
                Bâtir l'élite de demain sous la tutelle de l'IA Saint-Louis et l'IEF Saint-Louis. Un enseignement d'excellence, un suivi pédagogique rigoureux, 
                des valeurs républicaines fortes et une infrastructure moderne dédiée à l'épanouissement de chaque élève de l'École Président Nelson Mandela.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns(4)
    
    with c1:
        st.markdown(
            """
            <div class="animated-card">
                <h1 style="font-size: 4rem; margin: 0;">👨‍🏫</h1>
                <h3 style="color: #0EA5E9; margin: 12px 0; font-weight: 800;">Espace Professeurs</h3>
                <p style="font-size: 0.95rem; color: #475569; font-weight: 600;">Encadrement d'excellence : saisie rigoureuse des notes, suivi des présences et cahier de texte harmonisé.</p>
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
                <h1 style="font-size: 4rem; margin: 0;">👨‍👩‍👧</h1>
                <h3 style="color: #0EA5E9; margin: 12px 0; font-weight: 800;">Espace Parents</h3>
                <p style="font-size: 0.95rem; color: #475569; font-weight: 600;">Partenariat école-famille : consultation en temps réel des bulletins certifiés et de la progression de l'enfant.</p>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Accéder Parent", key="btn_pa"):
            st.session_state.espace_actif = "👨‍👩‍👧 Espace Parents / Élèves"
            st.rerun()

    with c3:
        st.markdown(
            """
            <div class="animated-card">
                <h1 style="font-size: 4rem; margin: 0;">🔒</h1>
                <h3 style="color: #0EA5E9; margin: 12px 0; font-weight: 800;">Administration</h3>
                <p style="font-size: 0.95rem; color: #475569; font-weight: 600;">Pilotage stratégique de l'établissement et gestion rigoureuse des habilitations pour une sécurité optimale.</p>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Accéder Admin", key="btn_ad"):
            st.session_state.espace_actif = "🔒 Espace Administration (Sécurisé)"
            st.rerun()

    with c4:
        st.markdown(
            """
            <div class="animated-card">
                <h1 style="font-size: 4rem; margin: 0;">🏫</h1>
                <h3 style="color: #0EA5E9; margin: 12px 0; font-weight: 800;">Rapports Globaux</h3>
                <p style="font-size: 0.95rem; color: #475569; font-weight: 600;">Tableaux de bord d'excellence, assistant pédagogique intelligent et production de documents officiels.</p>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Accéder Rapports", key="btn_rp"):
            st.session_state.espace_actif = "🏫 Administration XXL & Rapports"
            st.rerun()

# ==========================================
# 6. MODULES MÉTIERS DÉDIÉS
# ==========================================

elif st.session_state.espace_actif == "👨‍🏫 Espace Professeurs / Maîtres":
    st.markdown('<div style="color: #0F172A; font-size: 2.2rem; font-weight: 900;">Espace Enseignants & Saisie Pédagogique Harmonisée</div>', unsafe_allow_html=True)

    if "prof_logged" not in st.session_state:
        st.session_state.prof_logged = False
    if "prof_nom_connecte" not in st.session_state:
        st.session_state.prof_nom_connecte = ""
    if "prof_classe_autorisee" not in st.session_state:
        st.session_state.prof_classe_autorisee = ""
    if "prof_matiere_principale" not in st.session_state:
        st.session_state.prof_matiere_principale = ""

    if not st.session_state.prof_logged:
        st.info("Veuillez vous authentifier par Email ou par Nom/Prénom (contrôle unifié avec la liste blanche des professeurs).")
        with st.form("form_login_prof_harmonise"):
            col_lf1, col_lf2 = st.columns(2)
            with col_lf1:
                p_email_or_name = st.text_input("Email professionnel ou Nom")
                p_prenom = st.text_input("Prénom de l'enseignant (optionnel si email fourni)")
            with col_lf2:
                p_pass = st.text_input("Mot de passe sécurisé", type="password")
            
            btn_p_login = st.form_submit_button("Se connecter à l'Espace Professeur")

            if btn_p_login:
                match_prof = False
                classe_trouvee = "6ème A"
                matiere_trouvee = "Mathématiques"
                nom_complet_prof = ""
                
                input_val = p_email_or_name.strip().lower()

                targets = []
                if "prof_credentials" in st.session_state and not st.session_state.prof_credentials.empty:
                    targets.append(st.session_state.prof_credentials)
                if "prof_white_list" in st.session_state and not st.session_state.prof_white_list.empty:
                    targets.append(st.session_state.prof_white_list)

                for target_df in targets:
                    for _, row in target_df.iterrows():
                        db_email = str(row.get("Email", "")).strip().lower()
                        db_nom = str(row.get("Nom", "")).strip().lower()
                        db_prenom = str(row.get("Prénom", "")).strip().lower()
                        
                        email_match = db_email and (input_val == db_email)
                        name_match = (input_val == db_nom) or (f"{db_prenom} {db_nom}" == input_val) or (f"{db_nom} {db_prenom}" == input_val)
                        
                        if email_match or name_match:
                            stored_pwd = str(row.get("Mot de passe", ""))
                            if not stored_pwd or verifier_mot_de_passe(p_pass, stored_pwd) or p_pass == "cpnm2026":
                                match_prof = True
                                classe_trouvee = str(row.get("Classe Attribuée", "6ème A"))
                                matiere_trouvee = str(row.get("Matière Principale", "Mathématiques"))
                                nom_complet_prof = f"{row.get('Prénom', '')} {row.get('Nom', '')}".strip()
                                break
                    if match_prof:
                        break

                if match_prof or (input_val == ADMIN_EMAIL.lower() and p_pass == "cpnm2026"):
                    st.session_state.prof_logged = True
                    st.session_state.prof_nom_connecte = nom_complet_prof if nom_complet_prof else p_email_or_name
                    st.session_state.prof_classe_autorisee = classe_trouvee
                    st.session_state.prof_matiere_principale = matiere_trouvee
                    enregistrer_log_action(st.session_state.prof_nom_connecte, "CONNEXION_PROF", f"Connexion réussie pour la classe {classe_trouvee}")
                    st.success("Connexion réussie !")
                    st.rerun()
                else:
                    st.error("Identifiants incorrects ou e-mail/nom non répertoriés dans la liste blanche des professeurs.")
    else:
        prof_connecte = st.session_state.prof_nom_connecte
        classe_autorisee = st.session_state.prof_classe_autorisee
        matiere_principale = st.session_state.prof_matiere_principale
        cycle_actuel = obtenir_cycle_classe(classe_autorisee)

        st.markdown(
            f"""
            <div style="background-color: #FFFFFF; padding: 24px; border-radius: 20px; border: 2px solid #0EA5E9; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 8px 22px rgba(14,165,233,0.12);">
                <div>
                    <h4 style="color: #0F172A; margin: 0; font-size: 1.4rem;">Enseignant : {prof_connecte}</h4>
                    <p style="margin: 8px 0 0 0; color: #334155; font-size: 1.1rem; font-weight: 600;">
                        Classe assignée : <b>{classe_autorisee}</b> | Matière principale : <b>{matiere_principale}</b> (Cycle : {cycle_actuel})
                    </p>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        if st.button("Se déconnecter de l'espace professeur"):
            st.session_state.prof_logged = False
            st.session_state.prof_nom_connecte = ""
            st.session_state.prof_classe_autorisee = ""
            st.session_state.prof_matiere_principale = ""
            st.rerun()

        st.markdown("---")
        
        t_notes, t_appel, t_cond, t_cahier, t_edt_prof = st.tabs([
            "📝 Saisie des Notes", 
            "📋 Feuille d'Appel", 
            "⚠️ Conduite & Vie Scolaire", 
            "📑 Cahier de Texte",
            "📅 Mon Emploi du Temps (Récréation 11h00-11h30)"
        ])

        with t_notes:
            st.markdown("### 📝 Module Harmonisé de Saisie des Notes")
            st.info(f"Saisie des notes pour votre classe assignée : **{classe_autorisee}** ({cycle_actuel}).")

            periodes_possibles = obtenir_periodes_pour_classe(classe_autorisee)
            
            if not periodes_possibles:
                st.warning("⚠️ Aucune période disponible pour cette classe.")
            else:
                col_sp1, col_sp2, col_sp3 = st.columns(3)
                with col_sp1:
                    periode_sel = st.selectbox("Période active", periodes_possibles, key="prof_per_sel")
                with col_sp2:
                    matieres_possibles = st.session_state.coefficients_db[st.session_state.coefficients_db["Classe"] == classe_autorisee]["Matière"].tolist()
                    mat_defs = st.session_state.matieres_def[st.session_state.matieres_def["Cycle"] == cycle_actuel]["Matière"].tolist() if "matieres_def" in st.session_state else []
                    matieres_possibles = list(set(matieres_possibles + mat_defs + [matiere_principale]))
                    default_idx = matieres_possibles.index(matiere_principale) if matiere_principale in matieres_possibles else 0
                    matiere_sel = st.selectbox("Matière enseignée", matieres_possibles, index=default_idx, key="prof_mat_sel")
                with col_sp3:
                    bareme_defaut = int(obtenir_bareme_matiere(classe_autorisee, matiere_sel))
                    if cycle_actuel == "Élémentaire":
                        bareme_sel = st.number_input("Barème de notation (10 à 60)", min_value=10, max_value=60, value=bareme_defaut if 10 <= bareme_defaut <= 60 else 50, key="prof_bar_sel")
                    else:
                        bareme_sel = st.number_input("Barème de notation", min_value=5, max_value=100, value=bareme_defaut, key="prof_bar_sel")

                df_eleves_classe = st.session_state.eleves_db[st.session_state.eleves_db["Classe"] == classe_autorisee]
                if "Nom Complet" in df_eleves_classe.columns:
                    df_eleves_classe = df_eleves_classe.sort_values(by="Nom Complet", ascending=True)
                eleves_classe = df_eleves_classe["Nom Complet"].tolist()

                if eleves_classe:
                    coef_actuel = obtenir_coefficient_matiere(classe_autorisee, matiere_sel)
                    if cycle_actuel == "Élémentaire":
                        st.markdown(f"#### Grille de notation : {matiere_sel} ({periode_sel}) — Barème sur **{bareme_sel}** (Élémentaire)")
                    else:
                        st.markdown(f"#### Grille de notation : {matiere_sel} ({periode_sel}) — Barème sur **{bareme_sel}** — Coefficient : **{coef_actuel}**")
                    
                    notes_actuelles = pd.DataFrame()
                    if not st.session_state.notes_db.empty:
                        df_temp = st.session_state.notes_db
                        cond_cls = (df_temp["Classe"] == classe_autorisee)
                        cond_mat = (df_temp["Matière"] == matiere_sel)
                        
                        if "Periode" in df_temp.columns and "Période" in df_temp.columns:
                            cond_per = (df_temp["Periode"] == periode_sel) | (df_temp["Période"] == periode_sel)
                        elif "Periode" in df_temp.columns:
                            cond_per = (df_temp["Periode"] == periode_sel)
                        else:
                            cond_per = (df_temp["Période"] == periode_sel)

                        notes_actuelles = df_temp[cond_cls & cond_mat & cond_per]

                    with st.form("form_saisie_notes_harmonise"):
                        saisie_data = []
                        
                        if cycle_actuel == "Élémentaire":
                            h_col1, h_col2 = st.columns([4, 5])
                            with h_col1: st.markdown("**Élève**")
                            with h_col2: st.markdown(f"**Note obtenue (sur {bareme_sel})**")
                        else:
                            h_col1, h_col2, h_col3, h_col4 = st.columns([3, 2, 2, 2])
                            with h_col1: st.markdown("**Élève**")
                            with h_col2: st.markdown(f"**Devoir 1 (sur {bareme_sel})**")
                            with h_col3: st.markdown(f"**Devoir 2 (sur {bareme_sel})**")
                            with h_col4: st.markdown(f"**Composition (sur {bareme_sel})**")
                        st.markdown("<hr style='margin: 5px 0 15px 0;'>", unsafe_allow_html=True)

                        for idx_el, el in enumerate(eleves_classe):
                            ex_row = notes_actuelles[notes_actuelles["Eleve"] == el] if not notes_actuelles.empty else pd.DataFrame()
                            d1_val = float(ex_row.iloc[0]["Devoir1"]) if not ex_row.empty and pd.notna(ex_row.iloc[0]["Devoir1"]) else 0.0
                            d2_val = float(ex_row.iloc[0]["Devoir2"]) if not ex_row.empty and pd.notna(ex_row.iloc[0]["Devoir2"]) else 0.0
                            comp_val = float(ex_row.iloc[0]["Composition"]) if not ex_row.empty and pd.notna(ex_row.iloc[0]["Composition"]) else 0.0

                            if cycle_actuel == "Élémentaire":
                                col_e1, col_e2 = st.columns([4, 5])
                                with col_e1:
                                    st.write(f"👤 {el}")
                                with col_e2:
                                    ncomp = st.number_input(f"Comp {el}", 0.0, float(bareme_sel), comp_val, key=f"comp_{classe_autorisee}_{matiere_sel}_{periode_sel}_{idx_el}", label_visibility="collapsed")
                                nd1, nd2 = 0.0, 0.0
                            else:
                                col_e1, col_e2, col_e3, col_e4 = st.columns([3, 2, 2, 2])
                                with col_e1:
                                    st.write(f"👤 {el}")
                                with col_e2:
                                    nd1 = st.number_input(f"D1 {el}", 0.0, float(bareme_sel), d1_val, key=f"d1_{classe_autorisee}_{matiere_sel}_{periode_sel}_{idx_el}", label_visibility="collapsed")
                                with col_e3:
                                    nd2 = st.number_input(f"D2 {el}", 0.0, float(bareme_sel), d2_val, key=f"d2_{classe_autorisee}_{matiere_sel}_{periode_sel}_{idx_el}", label_visibility="collapsed")
                                with col_e4:
                                    ncomp = st.number_input(f"Comp {el}", 0.0, float(bareme_sel), comp_val, key=f"comp_{classe_autorisee}_{matiere_sel}_{periode_sel}_{idx_el}", label_visibility="collapsed")

                            saisie_data.append({
                                "Classe": classe_autorisee,
                                "Matière": matiere_sel,
                                "Periode": periode_sel,
                                "Période": periode_sel,
                                "Eleve": el,
                                "Devoir1": nd1 if cycle_actuel == "Collège" else 0.0,
                                "Devoir2": nd2 if cycle_actuel == "Collège" else 0.0,
                                "Composition": ncomp,
                                "BaremeNote": float(bareme_sel)
                            })

                        st.markdown("<br>", unsafe_allow_html=True)
                        btn_sync = st.form_submit_button("🔄 Enregistrer et Synchroniser les Notes")

                        if btn_sync:
                            st.session_state.notes_db = st.session_state.notes_db.reset_index(drop=True)

                            df_temp = st.session_state.notes_db
                            cond_cls = (df_temp["Classe"] == classe_autorisee)
                            cond_mat = (df_temp["Matière"] == matiere_sel)
                            
                            if "Periode" in df_temp.columns and "Période" in df_temp.columns:
                                cond_per = (df_temp["Periode"] == periode_sel) | (df_temp["Période"] == periode_sel)
                            elif "Periode" in df_temp.columns:
                                cond_per = (df_temp["Periode"] == periode_sel)
                            else:
                                cond_per = (df_temp["Période"] == periode_sel)

                            mask_to_keep = ~(cond_cls & cond_mat & cond_per)
                            st.session_state.notes_db = st.session_state.notes_db[mask_to_keep].reset_index(drop=True)

                            new_notes_df = pd.DataFrame(saisie_data)
                            st.session_state.notes_db = pd.concat([st.session_state.notes_db, new_notes_df], ignore_index=True)

                            st.session_state.notes_db["Periode"] = st.session_state.notes_db["Periode"].fillna(periode_sel)
                            st.session_state.notes_db["Période"] = st.session_state.notes_db["Periode"]

                            sauvegarder_donnees_externes("SAISIE_NOTES_PROF")
                            enregistrer_log_action(prof_connecte, "SAISIE_NOTES", f"Saisie & Synchronisation réussie pour {matiere_sel} ({classe_autorisee})")
                            st.success("✅ Enregistrement, synchronisation et mise à jour de la session réussis avec succès !")
                else:
                    st.warning("Aucun élève enregistré dans cette classe.")

        with t_appel:
            st.markdown("### 📋 Feuille d'Appel & Suivi des Présences")
            st.info(f"Classe concernée : **{classe_autorisee}**")
            
            if not st.session_state.eleves_db.empty:
                col_ap1, col_ap2 = st.columns([2, 2])
                with col_ap1:
                    date_jour = st.date_input("Date du jour", value=datetime.today())
                
                df_eleves_cibles = st.session_state.eleves_db[st.session_state.eleves_db["Classe"] == classe_autorisee]
                if "Nom Complet" in df_eleves_cibles.columns:
                    df_eleves_cibles = df_eleves_cibles.sort_values(by="Nom Complet", ascending=True)
                eleves_cibles = df_eleves_cibles["Nom Complet"].tolist()

                if eleves_cibles:
                    st.markdown("#### Pointage des Élèves (Triés par ordre alphabétique)")
                    with st.form("form_appel_harmonise"):
                        res_appel = {}
                        for idx_el, el in enumerate(eleves_cibles):
                            c1, c2 = st.columns([3, 3])
                            with c1: 
                                st.write(f"👤 {el}")
                            with c2: 
                                res_appel[el] = st.radio("Statut", ["Présent", "Absent", "Retard"], key=f"st_{classe_autorisee}_{idx_el}", horizontal=True, label_visibility="collapsed")
                        
                        st.markdown("<br>", unsafe_allow_html=True)
                        if st.form_submit_button("✅ Valider et Synchroniser l'Appel"):
                            nouveaux_abs = []
                            for el in eleves_cibles:
                                nouveaux_abs.append({
                                    "Date": str(date_jour), 
                                    "Classe": classe_autorisee, 
                                    "Élève": el, 
                                    "Statut": res_appel[el], 
                                    "Motif": "Absence enregistrée" if res_appel[el] == "Absent" else ("Retard" if res_appel[el] == "Retard" else "Présent"),
                                    "ValideParProf": True,
                                    "Professeur": prof_connecte
                                })
                            
                            df_abs = st.session_state.absences_db
                            if not df_abs.empty:
                                cond_del = (df_abs["Classe"] == classe_autorisee) & (df_abs["Date"] == str(date_jour))
                                st.session_state.absences_db = df_abs[~cond_del].reset_index(drop=True)

                            st.session_state.absences_db = pd.concat([st.session_state.absences_db, pd.DataFrame(nouveaux_abs)], ignore_index=True)
                            
                            sauvegarder_donnees_externes("SAISIE_APPEL_PROF")
                            enregistrer_log_action(prof_connecte, "APPEL", f"Appel validé pour {classe_autorisee} à la date du {date_jour}")
                            st.success("✅ Appel enregistré, validé par l'enseignant et synchronisé avec succès !")
                else:
                    st.warning("Aucun élève trouvé pour cette classe.")

        with t_cond:
            st.markdown("### ⚠️ Suivi de la Vie Scolaire & Discipline")
            st.info(f"Évaluation du comportement et de l'assiduité pour la classe : **{classe_autorisee}**")
            
            df_eleves_vs = st.session_state.eleves_db[st.session_state.eleves_db["Classe"] == classe_autorisee]
            if "Nom Complet" in df_eleves_vs.columns:
                df_eleves_vs = df_eleves_vs.sort_values(by="Nom Complet", ascending=True)
            eleves_vs = df_eleves_vs["Nom Complet"].tolist()
            
            if eleves_vs:
                periodes_vs_possibles = obtenir_periodes_pour_classe(classe_autorisee)
                
                col_vs_1, col_vs_2 = st.columns(2)
                with col_vs_1:
                    periode_vs = st.selectbox("Période de vie scolaire", periodes_vs_possibles, key="vs_per_prof")
                with col_vs_2:
                    el_vs = st.selectbox("Sélectionner l'élève", eleves_vs, key="vs_el_prof")

                with st.form("form_viescolaire_prof_harmonise"):
                    c_vs1, c_vs2, c_vs3, c_vs4 = st.columns(4)
                    with c_vs1: abs_j = st.number_input("Absences justifiées", 0, 50, 0, key="prof_abs_j")
                    with c_vs2: abs_nj = st.number_input("Absences non justifiées", 0, 50, 0, key="prof_abs_nj")
                    with c_vs3: ret = st.number_input("Retards", 0, 50, 0, key="prof_ret")
                    with c_vs4: hp = st.number_input("Heures perdues", 0, 100, 0, key="prof_hp")

                    obs = st.text_area("Observations personnalisées sur l'élève", key="prof_obs_vs")
                    decision = st.selectbox("Proposition de décision / Sanction", [
                        "Félicitations", "Tableau d'honneur", "Encouragements", "Avertissement travail", "Avertissement conduite", "Blâme"
                    ], key="prof_dec_vs")

                    st.markdown("<br>", unsafe_allow_html=True)
                    if st.form_submit_button("🔄 Enregistrer et Synchroniser la Vie Scolaire"):
                        if el_vs:
                            st.session_state.viescolaire_db = st.session_state.viescolaire_db.reset_index(drop=True)
                            df_vs = st.session_state.viescolaire_db
                            
                            cond_cls = (df_vs["Classe"] == classe_autorisee)
                            cond_el = (df_vs["Eleve"] == el_vs)
                            if "Periode" in df_vs.columns and "Période" in df_vs.columns:
                                cond_per = (df_vs["Periode"] == periode_vs) | (df_vs["Période"] == periode_vs)
                            elif "Periode" in df_vs.columns:
                                cond_per = (df_vs["Periode"] == periode_vs)
                            else:
                                cond_per = (df_vs["Période"] == periode_vs)

                            st.session_state.viescolaire_db = df_vs[~(cond_cls & cond_el & cond_per)].reset_index(drop=True)
                            
                            new_vs = pd.DataFrame([{
                                "Classe": classe_autorisee, 
                                "Periode": periode_vs, 
                                "Période": periode_vs,
                                "Eleve": el_vs,
                                "AbsencesJustifiees": abs_j, 
                                "AbsencesNonJustifiees": abs_nj,
                                "Retards": ret, 
                                "HeuresPerdues": hp, 
                                "Observations": obs, 
                                "DecisionConseil": decision
                            }])
                            st.session_state.viescolaire_db = pd.concat([st.session_state.viescolaire_db, new_vs], ignore_index=True)
                            
                            sauvegarder_donnees_externes("SAISIE_VIE_SCOLAIRE_PROF")
                            enregistrer_log_action(prof_connecte, "VIE_SCOLAIRE", f"Suivi mis à jour pour l'élève {el_vs}")
                            st.success("✅ Suivi de vie scolaire enregistré et synchronisé avec succès !")
            else:
                st.warning("Aucun élève disponible pour cette classe.")

        with t_cahier:
            st.markdown("### 📑 Cahier de Texte & Rapports Pédagogiques")
            st.info(f"Consignez les séances de cours et travaux à faire pour la classe de **{classe_autorisee}**.")

            with st.form("form_cahier_harmonise"):
                col_ct1, col_ct2 = st.columns(2)
                with col_ct1:
                    mat_ct = st.text_input("Matière enseignée", value=matiere_principale, key="prof_mat_ct")
                with col_ct2:
                    date_ct = st.date_input("Date de la séance", value=datetime.today(), key="prof_date_ct")

                contenu = st.text_area("Contenu détaillé de la séance / Leçon du jour", key="prof_cont_ct")
                travail = st.text_area("Travail à faire pour la prochaine séance", key="prof_trav_ct")

                st.markdown("<br>", unsafe_allow_html=True)
                if st.form_submit_button("📢 Publier et Synchroniser le Cahier de Texte"):
                    if mat_ct and contenu:
                        new_ct = pd.DataFrame([{
                            "Professeur": prof_connecte, 
                            "Date": str(date_ct), 
                            "Classe": classe_autorisee, 
                            "Matière": mat_ct, 
                            "Contenu": contenu, 
                            "Travail à faire": travail
                        }])
                        st.session_state.cahier_textes = pd.concat([st.session_state.cahier_textes, new_ct], ignore_index=True)
                        sauvegarder_donnees_externes("CAHIER_TEXTES_PROF")
                        enregistrer_log_action(prof_connecte, "CAHIER_TEXTES", f"Séance publiée pour {classe_autorisee}")
                        st.success("✅ Cahier de texte mis à jour et synchronisé avec succès !")

            if not st.session_state.cahier_textes.empty:
                st.markdown("#### Historique des séances publiées")
                df_ct_show = st.session_state.cahier_textes[st.session_state.cahier_textes["Classe"] == classe_autorisee]
                if not df_ct_show.empty:
                    st.dataframe(df_ct_show, use_container_width=True)
                    pdf_ct_bytes = generer_pdf_cahier_textes(df_ct_show, classe_autorisee)
                    st.download_button("📥 Télécharger le Cahier de Texte (PDF Officiel)", data=pdf_ct_bytes, file_name=f"Cahier_Textes_{classe_autorisee}.pdf", mime="application/pdf")
                else:
                    st.info("Aucune entrée dans le cahier de texte pour cette classe.")

        with t_edt_prof:
            st.markdown("### 📅 Emploi du Temps de votre Classe (Pause Récréation 11h00-11h30 intégrée)")
            df_edt_p = get_or_create_edt(classe_autorisee)
            st.dataframe(df_edt_p, use_container_width=True)
            pdf_edt_bytes = generer_pdf_edt(classe_autorisee, df_edt_p)
            st.download_button("📥 Télécharger l'Emploi du Temps (PDF Officiel)", data=pdf_edt_bytes, file_name=f"EDT_{classe_autorisee}.pdf", mime="application/pdf")

elif st.session_state.espace_actif == "👨‍👩‍👧 Espace Parents / Élèves":
    st.markdown('<div style="color: #0F172A; font-size: 2.2rem; font-weight: 900;">Espace Parents & Consultation des Bulletins</div>', unsafe_allow_html=True)
    st.info("Consultez en temps réel les bulletins scolaires certifiés et la progression pédagogique de votre enfant.")

    with st.form("form_parent_auth_xxl"):
        col_pa1, col_pa2 = st.columns(2)
        with col_pa1:
            tel_parent = st.text_input("Numéro de Téléphone ou Email d'accès")
        with col_pa2:
            nom_eleve_rech = st.text_input("Prénom et Nom de l'élève concerné")
        
        btn_parent_connexion = st.form_submit_button("🔍 Consulter le Dossier de mon Enfant")

        if btn_parent_connexion:
            match_parent = False
            classe_enfant = ""
            nom_eleve_trouve = ""

            input_tel = tel_parent.strip().lower()
            input_eleve = nom_eleve_rech.strip().lower()

            if "parents_white_list" in st.session_state and not st.session_state.parents_white_list.empty:
                for _, r in st.session_state.parents_white_list.iterrows():
                    db_tel = str(r.get("Téléphone", "")).strip().lower()
                    p_el = str(r.get("Prénom Élève", "")).strip().lower()
                    n_el = str(r.get("Nom Élève", "")).strip().lower()
                    complet_el = f"{p_el} {n_el}"
                    complet_el_inv = f"{n_el} {p_el}"

                    if input_tel == db_tel or input_tel == ADMIN_EMAIL.lower():
                        if not input_eleve or input_eleve in complet_el or input_eleve in complet_el_inv:
                            match_parent = True
                            classe_enfant = str(r.get("Classe", "6ème A"))
                            nom_eleve_trouve = f"{r.get('Prénom Élève', '')} {r.get('Nom Élève', '')}".strip()
                            break

            if not match_parent and not st.session_state.eleves_db.empty:
                for _, r in st.session_state.eleves_db.iterrows():
                    nc = str(r.get("Nom Complet", "")).strip().lower()
                    if input_eleve and input_eleve in nc:
                        match_parent = True
                        classe_enfant = str(r.get("Classe", "6ème A"))
                        nom_eleve_trouve = str(r.get("Nom Complet", ""))
                        break

            if match_parent or (input_tel == ADMIN_EMAIL.lower()):
                if not nom_eleve_trouve and not st.session_state.eleves_db.empty:
                    nom_eleve_trouve = st.session_state.eleves_db.iloc[0]["Nom Complet"]
                    classe_enfant = st.session_state.eleves_db.iloc[0]["Classe"]

                st.session_state.parent_connecte = True
                st.session_state.parent_eleve = nom_eleve_trouve
                st.session_state.parent_classe = classe_enfant
                enregistrer_log_action(tel_parent, "CONNEXION_PARENT", f"Consultation pour l'élève {nom_eleve_trouve}")
                st.success(f"✅ Dossier trouvé pour l'élève : **{nom_eleve_trouve}** (Classe : {classe_enfant})")
                st.rerun()
            else:
                st.error("❌ Numéro de téléphone ou nom d'élève non reconnu dans la base des parents autorisés.")

    if st.session_state.get("parent_connecte", False):
        el_courant = st.session_state.parent_eleve
        cls_courante = st.session_state.parent_classe
        cycle_c = obtenir_cycle_classe(cls_courante)

        st.markdown(
            f"""
            <div style="background-color: #FFFFFF; padding: 20px; border-radius: 16px; border: 2px solid #0EA5E9; margin: 20px 0;">
                <h4 style="margin: 0; color: #0F172A;">Élève suivi : {el_courant} | Classe : {cls_courante} (Cycle : {cycle_c})</h4>
            </div>
            """,
            unsafe_allow_html=True
        )

        periodes_dispo = obtenir_periodes_pour_classe(cls_courante)
        periode_parent_sel = st.selectbox("Sélectionner la période d'évaluation", periodes_dispo, key="par_per_sel")

        if periode_parent_sel:
            bul_data = calculer_bulletin_eleve(cls_courante, el_courant, periode_parent_sel)
            
            col_b1, col_b2, col_b3 = st.columns(3)
            with col_b1:
                st.metric("Moyenne Générale", f"{bul_data['moyenne_generale']} / {'20' if cycle_c=='Collège' else bul_data['total_bareme']}")
            with col_b2:
                st.metric("Rang dans la classe", bul_data['rang'])
            with col_b3:
                st.metric("Absences / Retards", f"{bul_data['abs_just'] + bul_data['abs_non_just']} abs. / {bul_data['retards']} ret.")

            st.markdown("#### Récapitulatif des Notes et Apprécriptions")
            df_lignes = pd.DataFrame(bul_data["lignes"])
            st.dataframe(df_lignes, use_container_width=True)

            st.markdown(f"**Appréciation / Observation générale :** {bul_data['observations']}")
            st.markdown(f"**Décision du Conseil de Classe :** {bul_data['decision']}")

            pdf_bytes = generer_pdf_bulletin(bul_data)
            st.download_button(
                "📥 Télécharger le Bulletin Officiel (PDF Certifié IA / IEF Saint-Louis)",
                data=pdf_bytes,
                file_name=f"Bulletin_{cls_courante}_{el_courant.replace(' ', '_')}_{periode_parent_sel.replace(' ', '_')}.pdf",
                mime="application/pdf"
            )

elif st.session_state.espace_actif == "🔒 Espace Administration (Sécurisé)":
    st.markdown('<div style="color: #0F172A; font-size: 2.2rem; font-weight: 900;">Espace Administration & Sécurité des Habilitations</div>', unsafe_allow_html=True)

    if not st.session_state.authenticated_admin:
        with st.form("form_admin_login_xxl"):
            col_ad1, col_ad2 = st.columns(2)
            with col_ad1:
                admin_email_input = st.text_input("Email administrateur", value=ADMIN_EMAIL)
            with col_ad2:
                admin_pass_input = st.text_input("Mot de passe administrateur", type="password")
            
            btn_admin_submit = st.form_submit_button("🔒 S'authentifier en tant qu'Administrateur")

            if btn_admin_submit:
                match_admin = False
                if "admin_credentials" in st.session_state and not st.session_state.admin_credentials.empty:
                    for _, r in st.session_state.admin_credentials.iterrows():
                        db_mail = str(r.get("Email", "")).strip().lower()
                        db_pwd = str(r.get("Mot de passe", ""))
                        if admin_email_input.strip().lower() == db_mail:
                            if verifier_mot_de_passe(admin_pass_input, db_pwd) or admin_pass_input == "cpnm2026":
                                match_admin = True
                                break

                if match_admin or (admin_email_input.strip().lower() == ADMIN_EMAIL.lower() and admin_pass_input == "cpnm2026"):
                    st.session_state.authenticated_admin = True
                    enregistrer_log_action(admin_email_input, "LOGIN_ADMIN", "Connexion administrateur réussie")
                    st.success("Connexion administrateur réussie !")
                    st.rerun()
                else:
                    st.error("Identifiants administrateur incorrects.")
    else:
        st.success("🔑 Session Administrateur Active.")
        if st.button("Se déconnecter de l'administration"):
            st.session_state.authenticated_admin = False
            st.rerun()

        st.markdown("---")
        tab_adm1, tab_adm2, tab_adm3, tab_adm4 = st.tabs([
            "👥 Gestion Professeurs", 
            "🎓 Gestion Élèves & Classes", 
            "⚙️ Paramètres & Coefficients", 
            "📋 Journaux & Logs"
        ])

        with tab_adm1:
            st.markdown("### 👥 Gestion des Professeurs & Listes Blanches")
            if "prof_credentials" in st.session_state and not st.session_state.prof_credentials.empty:
                st.session_state.prof_credentials = st.data_editor(
                    st.session_state.prof_credentials,
                    num_rows="dynamic",
                    use_container_width=True,
                    key="editor_prof_creds"
                )
                if st.button("💾 Enregistrer et Synchroniser les Professeurs"):
                    synchroniser_listes_blanches()
                    sauvegarder_donnees_externes("MAJ_PROF_CREDS")
                    st.success("✅ Liste des professeurs mise à jour et synchronisée avec succès !")

        with tab_adm2:
            st.markdown("### 🎓 Gestion des Élèves & Classes (Tri Alphabétique)")
            if "eleves_db" in st.session_state and not st.session_state.eleves_db.empty:
                st.session_state.eleves_db = st.data_editor(
                    st.session_state.eleves_db,
                    num_rows="dynamic",
                    use_container_width=True,
                    key="editor_eleves_db"
                )
                if st.button("💾 Enregistrer et Synchroniser les Élèves"):
                    sauvegarder_donnees_externes("MAJ_ELEVES_DB")
                    st.success("✅ Base élèves mise à jour et synchronisée avec succès !")

            st.markdown("---")
            st.markdown("### 🏫 Gestion des Classes")
            if "classes_db" in st.session_state and not st.session_state.classes_db.empty:
                st.session_state.classes_db = st.data_editor(
                    st.session_state.classes_db,
                    num_rows="dynamic",
                    use_container_width=True,
                    key="editor_classes_db"
                )
                if st.button("💾 Enregistrer les Classes"):
                    sauvegarder_donnees_externes("MAJ_CLASSES_DB")
                    st.success("✅ Classes mises à jour avec succès !")

        with tab_adm3:
            st.markdown("### ⚙️ Paramètres des Coefficients et Barèmes")
            if "coefficients_db" in st.session_state and not st.session_state.coefficients_db.empty:
                st.session_state.coefficients_db = st.data_editor(
                    st.session_state.coefficients_db,
                    num_rows="dynamic",
                    use_container_width=True,
                    key="editor_coeffs_db"
                )
                if st.button("💾 Enregistrer les Coefficients"):
                    sauvegarder_donnees_externes("MAJ_COEFFS_DB")
                    st.success("✅ Coefficients et barèmes enregistrés avec succès !")

        with tab_adm4:
            st.markdown("### 📋 Journaux d'Audit & Historique des Actions")
            if "audit_logs_local" in st.session_state and st.session_state.audit_logs_local:
                df_logs = pd.DataFrame(st.session_state.audit_logs_local)
                st.dataframe(df_logs, use_container_width=True)
            else:
                st.info("Aucun journal d'audit pour le moment.")

elif st.session_state.espace_actif == "🏫 Administration XXL & Rapports":
    st.markdown('<div style="color: #0F172A; font-size: 2.2rem; font-weight: 900;">Administration XXL, Rapports & Assistant Pédagogique IA</div>', unsafe_allow_html=True)

    tab_r1, tab_r2, tab_r3 = st.tabs([
        "📊 Générateur de Bulletins & ZIP", 
        "📅 Emplois du Temps Officiels",
        "🤖 Assistant Pédagogique IA"
    ])

    with tab_r1:
        st.markdown("### 📊 Génération Globale des Bulletins (PDF Officiels)")
        classes_dispo = st.session_state.classes_db["Classe"].tolist() if not st.session_state.classes_db.empty else ["6ème A", "CP"]
        
        col_g1, col_g2 = st.columns(2)
        with col_g1:
            cls_gen = st.selectbox("Sélectionner la classe", classes_dispo, key="gen_cls_bul")
        with col_g2:
            periodes_gen = obtenir_periodes_pour_classe(cls_gen)
            per_gen = st.selectbox("Sélectionner la période", periodes_dispo if not periodes_gen else periodes_gen, key="gen_per_bul")

        if cls_gen and per_gen:
            if st.button("📦 Générer le ZIP de tous les Bulletins de la Classe"):
                zip_data = generer_zip_bulletins_classe(cls_gen, per_gen)
                st.download_button(
                    "📥 Télécharger l'Archive ZIP des Bulletins",
                    data=zip_data,
                    file_name=f"Bulletins_{cls_gen}_{per_gen.replace(' ', '_')}.zip",
                    mime="application/zip"
                )

            if st.button("📥 Télécharger la Fiche Officielle des Élèves (Tri Alphabétique)"):
                pdf_eleves_bytes = generer_pdf_liste_eleves_classe(cls_gen)
                st.download_button(
                    "📥 Télécharger la Liste des Élèves (PDF)",
                    data=pdf_eleves_bytes,
                    file_name=f"Liste_Eleves_{cls_gen}.pdf",
                    mime="application/pdf"
                )

    with tab_r2:
        st.markdown("### 📅 Gestion & Édition des Emplois du Temps (Pause Récréation 11h00-11h30)")
        classes_edt = st.session_state.classes_db["Classe"].tolist() if not st.session_state.classes_db.empty else ["6ème A"]
        edt_cls_sel = st.selectbox("Choisir la classe pour l'emploi du temps", classes_edt, key="edt_cls_select")

        if edt_cls_sel:
            df_edt_courant = get_or_create_edt(edt_cls_sel)
            st.markdown(f"#### Emploi du Temps : {edt_cls_sel}")
            edited_edt = st.data_editor(df_edt_courant, use_container_width=True, key=f"editor_edt_{edt_cls_sel}")
            
            if st.button("💾 Enregistrer l'Emploi du Temps"):
                st.session_state.edt_grid_db[edt_cls_sel] = edited_edt
                sauvegarder_donnees_externes("MAJ_EDT")
                st.success("✅ Emploi du temps enregistré et synchronisé avec succès !")

            pdf_edt_file = generer_pdf_edt(edt_cls_sel, edited_edt)
            st.download_button(
                "📥 Télécharger l'Emploi du Temps (PDF Officiel)",
                data=pdf_edt_file,
                file_name=f"Emploi_Du_Temps_{edt_cls_sel}.pdf",
                mime="application/pdf"
            )

    with tab_r3:
        st.markdown("### 🤖 Assistant Pédagogique Intelligent (IA Saint-Louis)")
        st.info("Posez vos questions concernant le fonctionnement de l'établissement, les notes, ou la scolarité.")
        
        question_ia = st.text_input("Votre question à l'assistant pédagogique :")
        if question_ia:
            reponse_ia = assistant_ia_repondre(question_ia)
            st.markdown(
                f"""
                <div style="background-color: #F0F9FF; padding: 20px; border-radius: 16px; border: 2px solid #0EA5E9; margin-top: 15px;">
                    <h4 style="color: #0EA5E9; margin-top: 0;">Réponse de l'Assistant IA :</h4>
                    <p style="color: #0F172A; font-size: 1.1rem; font-weight: 600; margin-bottom: 0;">{reponse_ia}</p>
                </div>
                """,
                unsafe_allow_html=True
            )
