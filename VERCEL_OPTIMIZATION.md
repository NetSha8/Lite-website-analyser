# Heimdall - Vercel Deployment Optimizations

## 🎯 Optimisations pour réduire les coûts sur Vercel

### 1. **Cache Agressif**
- Analyses complètes: **30 minutes** (au lieu de 5)
- WHOIS: **24 heures** (au lieu de 1 heure)
- DNS: **1 heure** (au lieu de 5 minutes)
- Taille cache augmentée: 1000-2000 entrées

### 2. **Rate Limiting Strict**
- **10 requêtes/minute** par IP
- **50 requêtes/heure** par IP
- Protection contre les abus et spam

### 3. **Configuration Vercel**
- Région: `cdg1` (Paris - le plus proche)
- Timeout: 30 secondes max
- Mémoire: 512MB

### 4. **Réduction des Appels Externes**
- Trustpilot: weight=0 si non trouvé (pas de pénalité)
- Timeout réduit: 5 secondes pour Trustpilot
- Timeout: 10 secondes pour les autres requêtes
- Utilisation du cache partagé HTTP

## 📊 Impact Estimé

### Avant optimisations:
- ~200 analyses/jour = ~6000 requêtes externes
- Coût estimé: ~$5-10/mois

### Après optimisations:
- ~200 analyses/jour = ~1000 requêtes externes (80% cache hit)
- Coût estimé: ~$1-3/mois

## 🚀 Déploiement Vercel

```bash
# 1. Installer Vercel CLI
npm i -g vercel

# 2. Login
vercel login

# 3. Déployer
vercel --prod
```

## 💡 Conseils Supplémentaires

1. **Monitoring**: Vérifier `/api/stats` pour voir les stats du cache
2. **Rate Limit**: Augmenter si besoin selon l'usage réel
3. **Cache**: Ajuster les TTL selon la fréquence d'utilisation
4. **Logs**: Activer les logs Vercel pour surveiller les coûts

## ⚠️ Limites Gratuites Vercel

- **Serverless Functions**: 100 Go-hrs/mois
- **Bandwidth**: 100 GB/mois
- **Invocations**: 12M/mois

Avec les optimisations, tu devrais rester dans les limites gratuites pour un usage modéré.
