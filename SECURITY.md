# Politique de sécurité et d’utilisation

## Autorisation et limites éthiques

N’utilisez cet outil que sur un système dont vous êtes propriétaire ou pour lequel vous disposez d’une autorisation explicite et documentée. Scanner un tiers sans autorisation est interdit. L’audit est passif : GET uniquement dans l’implémentation distante, 20 requêtes au maximum, délai minimal d’une seconde, domaine strictement autorisé, aucune redirection inter-domaine, aucun contournement, aucune authentification et aucune modification distante.

Un nom de module, une route ou un asset ne confirme pas une vulnérabilité. Les statuts `REQUIRES_ACCESS` et `ASSET_RESIDUE` ne doivent jamais être présentés comme une compromission ou une vulnérabilité confirmée. Le laboratoire reste local, isolé, fictif et désactivé par défaut.

## Conservation des preuves

1. Restreindre l’accès au dossier `reports/`.
2. Conserver le rapport HTML avec son hash SHA-256 et la date UTC.
3. Ne pas enrichir les preuves avec des données personnelles; les cookies, tokens, e-mails, téléphones et paramètres sensibles sont masqués.
4. Documenter séparément toute preuve obtenue avec un accès serveur ou Back Office.
5. Définir une durée de rétention contractuelle puis supprimer les copies de façon contrôlée.

## Divulgation responsable

Valider d’abord le résultat avec le propriétaire dans un environnement contrôlé. Contacter l’éditeur ou le mainteneur via son canal de sécurité, transmettre une preuve minimale expurgée et laisser un délai raisonnable de correction avant toute publication. Pour PrestaShop et ses modules, privilégier les canaux officiels et Friends of Presta. Ne publiez jamais de secrets, données client ou procédure d’exploitation active.

Pour signaler une vulnérabilité dans LOGIALOG Security Auditor, ne créez pas d’issue publique. Le canal officiel est le formulaire GitHub **Report a vulnerability** du dépôt `logialog/prestashop-security-auditor`, disponible sur la page **Security advisories** une fois la fonction de signalement privé activée.

Le signalement doit contenir une description claire, l’impact estimé, les versions concernées et une reproduction minimale expurgée. N’incluez aucun secret, jeton, rapport client, donnée personnelle ou réponse HTTP non expurgée. Les mainteneurs examineront le signalement et coordonneront la validation, la correction et la divulgation dans l’espace privé de l’advisory.
