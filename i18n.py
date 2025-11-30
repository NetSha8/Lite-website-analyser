"""Internationalization (i18n) module for Heimdall."""

from typing import Any

# Supported languages
SUPPORTED_LANGUAGES = ["en", "fr"]
DEFAULT_LANGUAGE = "en"

# Translation dictionaries
TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        # Header
        "app_name": "Heimdall",
        "app_tagline": "Website Legitimacy Scanner",
        
        # Main page
        "analyze_title": "Analyze a website",
        "analyze_description": "Enter a website URL to check its legitimacy and detect phishing signs.",
        "url_placeholder": "https://example.com",
        "analyze_button": "Analyze",
        "analyzing_button": "Analyzing...",
        
        # Features
        "feature_domain_age_title": "Domain Age",
        "feature_domain_age_desc": "Checks how long the domain has been registered. Phishing sites are often very recent.",
        "feature_ssl_title": "SSL Certificate",
        "feature_ssl_desc": "Analyzes the validity and configuration of the site's SSL/TLS certificate.",
        "feature_content_title": "Content Analysis",
        "feature_content_desc": "Examines HTML code for suspicious patterns like phishing forms.",
        
        # Results
        "result_title": "Analysis Result",
        "risk_safe": "Safe",
        "risk_low": "Low Risk",
        "risk_medium": "Medium Risk",
        "risk_high": "High Risk",
        "risk_critical": "Critical",
        "view_details": "View details",
        
        # Score names
        "score_domain_age": "Domain Age",
        "score_ssl": "SSL Certificate",
        "score_url_pattern": "URL Pattern",
        "score_content": "Content Analysis",
        "score_dns": "DNS Analysis",
        
        # Summaries
        "summary_safe": "This website appears to be legitimate and trustworthy.",
        "summary_low": "This website appears mostly legitimate with minor concerns.",
        "summary_medium": "This website has some suspicious characteristics. Exercise caution.",
        "summary_high": "This website shows multiple warning signs. Be very careful.",
        "summary_critical": "This website is highly suspicious and potentially dangerous. Avoid interaction.",
        "summary_concerns": "Key concerns",
        "summary_errors": "Note: Some checks failed",
        
        # Errors
        "error_title": "Analysis Error",
        "error_validation": "Validation Error",
        "error_url_empty": "URL cannot be empty",
        "error_url_too_long": "URL is too long",
        "error_url_invalid": "Invalid URL format",
        "error_url_dangerous": "URL contains potentially dangerous content",
        "error_url_internal": "Access to internal resources is not allowed",
        "error_rate_limit": "Too many requests. Please wait before trying again.",
        
        # Footer
        "footer_text": "Heimdall - Protect yourself against phishing and fraudulent websites",
        
        # Language
        "language": "Language",
        "lang_en": "English",
        "lang_fr": "Français",
    },
    "fr": {
        # Header
        "app_name": "Heimdall",
        "app_tagline": "Scanner de Légitimité de Sites Web",
        
        # Main page
        "analyze_title": "Analyser un site web",
        "analyze_description": "Entrez l'URL d'un site pour vérifier sa légitimité et détecter les signes de phishing.",
        "url_placeholder": "https://example.com",
        "analyze_button": "Analyser",
        "analyzing_button": "Analyse...",
        
        # Features
        "feature_domain_age_title": "Âge du domaine",
        "feature_domain_age_desc": "Vérifie depuis combien de temps le domaine est enregistré. Les sites de phishing sont souvent très récents.",
        "feature_ssl_title": "Certificat SSL",
        "feature_ssl_desc": "Analyse la validité et la configuration du certificat SSL/TLS du site.",
        "feature_content_title": "Analyse du contenu",
        "feature_content_desc": "Examine le code HTML à la recherche de patterns suspects comme les formulaires de phishing.",
        
        # Results
        "result_title": "Résultat de l'analyse",
        "risk_safe": "Sûr",
        "risk_low": "Risque faible",
        "risk_medium": "Risque moyen",
        "risk_high": "Risque élevé",
        "risk_critical": "Critique",
        "view_details": "Voir les détails",
        
        # Score names
        "score_domain_age": "Âge du domaine",
        "score_ssl": "Certificat SSL",
        "score_url_pattern": "Pattern URL",
        "score_content": "Analyse contenu",
        "score_dns": "Analyse DNS",
        
        # Summaries
        "summary_safe": "Ce site web semble être légitime et digne de confiance.",
        "summary_low": "Ce site web semble principalement légitime avec des préoccupations mineures.",
        "summary_medium": "Ce site web présente des caractéristiques suspectes. Faites preuve de prudence.",
        "summary_high": "Ce site web présente plusieurs signes d'alerte. Soyez très prudent.",
        "summary_critical": "Ce site web est hautement suspect et potentiellement dangereux. Évitez toute interaction.",
        "summary_concerns": "Points d'attention",
        "summary_errors": "Note : Certaines vérifications ont échoué",
        
        # Errors
        "error_title": "Erreur d'analyse",
        "error_validation": "Erreur de validation",
        "error_url_empty": "L'URL ne peut pas être vide",
        "error_url_too_long": "L'URL est trop longue",
        "error_url_invalid": "Format d'URL invalide",
        "error_url_dangerous": "L'URL contient du contenu potentiellement dangereux",
        "error_url_internal": "L'accès aux ressources internes n'est pas autorisé",
        "error_rate_limit": "Trop de requêtes. Veuillez patienter avant de réessayer.",
        
        # Footer
        "footer_text": "Heimdall - Protégez-vous contre le phishing et les sites frauduleux",
        
        # Language
        "language": "Langue",
        "lang_en": "English",
        "lang_fr": "Français",
    },
}


def get_translation(key: str, lang: str = DEFAULT_LANGUAGE) -> str:
    """
    Get a translation for the given key and language.
    
    Args:
        key: The translation key
        lang: The language code (e.g., 'en', 'fr')
        
    Returns:
        The translated string, or the key if not found
    """
    if lang not in TRANSLATIONS:
        lang = DEFAULT_LANGUAGE
    
    return TRANSLATIONS[lang].get(key, TRANSLATIONS[DEFAULT_LANGUAGE].get(key, key))


def get_all_translations(lang: str = DEFAULT_LANGUAGE) -> dict[str, str]:
    """
    Get all translations for a language.
    
    Args:
        lang: The language code
        
    Returns:
        Dictionary of all translations
    """
    if lang not in TRANSLATIONS:
        lang = DEFAULT_LANGUAGE
    
    # Merge with default language as fallback
    result = TRANSLATIONS[DEFAULT_LANGUAGE].copy()
    result.update(TRANSLATIONS[lang])
    return result


def detect_language_from_header(accept_language: str | None) -> str:
    """
    Detect preferred language from Accept-Language header.
    
    Args:
        accept_language: The Accept-Language header value
        
    Returns:
        The detected language code
    """
    if not accept_language:
        return DEFAULT_LANGUAGE
    
    # Parse Accept-Language header
    # Example: "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"
    languages = []
    for part in accept_language.split(","):
        part = part.strip()
        if ";q=" in part:
            lang, q = part.split(";q=")
            try:
                quality = float(q)
            except ValueError:
                quality = 0.0
        else:
            lang = part
            quality = 1.0
        
        # Extract base language (e.g., "fr-FR" -> "fr")
        base_lang = lang.split("-")[0].lower()
        languages.append((base_lang, quality))
    
    # Sort by quality and find first supported language
    languages.sort(key=lambda x: x[1], reverse=True)
    
    for lang, _ in languages:
        if lang in SUPPORTED_LANGUAGES:
            return lang
    
    return DEFAULT_LANGUAGE
