import dns.resolver
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
import os


app = FastAPI(title="Email Shield API", version="1.0.0")

resolver = dns.resolver.Resolver()
resolver.timeout = 2      # Temps d'attente pour une réponse
resolver.lifetime = 2     # Temps total alloué à la requête

class EmailRequest(BaseModel):
    address: str

# Chargement de la base de données locale

base_path = os.path.dirname(__file__)
config_path = os.path.join(base_path, 'temp_email.conf')



try:
    with open(config_path, 'r') as f:
        BLACKLIST_LOCAL = {line.strip().lower() for line in f if line.strip()}
except FileNotFoundError:
    BLACKLIST_LOCAL = set()

# Configuration Pro
WHITELIST = {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "icloud.com", "protonmail.com"}
MX_KEYWORDS = {"yopmail", "mailinator", "tempmail", "disposable", "10minutemail", "guerrillamail", "jetable"}

@app.post("/v1/verify")
async def verify_email(payload: EmailRequest):
    email_input = payload.address.strip().lower()
    
    # Extraction du domaine
    if "@" not in email_input:
        return {
            "email": email_input,
            "disposable": True,
            "status": "invalid_format",
            "confidence": 1.0
        }
    
    domain = email_input.split("@")[-1]

    # --- ÉTAPE 1 : Whitelist (Vitesse) ---
    if domain in WHITELIST:
        return {
            "email": email_input,
            "domain": domain,
            "disposable": False,
            "status": "trusted_provider",
            "confidence": 1.0
        }

    # --- ÉTAPE 2 : Blacklist Locale ---
    if domain in BLACKLIST_LOCAL:
        return {
            "email": email_input,
            "domain": domain,
            "disposable": True,
            "status": "blacklisted",
            "confidence": 1.0
        }

    # --- ÉTAPE 3 : Deep DNS Analysis ---
    try:
        # Vérification des serveurs MX
        mx_records = resolver.resolve(domain, 'MX')
        mx_host = str(mx_records[0].exchange).lower().strip('.')

        # Check des mots-clés dans le nom du serveur MX
        if any(key in mx_host for key in MX_KEYWORDS):
            return {
                "email": email_input,
                "domain": domain,
                "disposable": True,
                "status": "disposable_infrastructure",
                "confidence": 0.98
            }

        # Check du "Site Fantôme" (Si le MX ressemble au domaine, on vérifie le Record A)
        if domain in mx_host:
            try:
                dns.resolver.resolve(domain, 'A')
            except:
                return {
                    "email": email_input,
                    "domain": domain,
                    "disposable": True,
                    "status": "no_web_presence",
                    "confidence": 0.90
                }

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return {
            "email": email_input,
            "domain": domain,
            "disposable": True,
            "status": "domain_not_found",
            "confidence": 1.0
        }
    except Exception:
        # En cas de timeout DNS, on ne bloque pas (évite les faux positifs)
        return {
            "email": email_input,
            "domain": domain,
            "disposable": False,
            "status": "analysis_incomplete",
            "confidence": 0.5
        }

    # Si tout est passé au vert
    return {
        "email": email_input,
        "domain": domain,
        "disposable": False,
        "status": "clean",
        "confidence": 0.85
    }