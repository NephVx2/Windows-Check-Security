#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Audit de sécurité complet pour Windows 11
.DESCRIPTION
    Ce script effectue un audit de sécurité complet d'un poste Windows 11 :
    - Informations système
    - Windows Update & patches
    - Pare-feu Windows
    - Antivirus / Windows Defender
    - Comptes utilisateurs & politiques de mots de passe (dont compte Administrator RID-500)
    - Services critiques
    - Partages réseau
    - Audit des droits & UAC
    - Chiffrement BitLocker
    - Protocoles réseau (SMB, RDP, etc.) + IPv6 exposition pare-feu
    - Connexions TCP établies vers IPs publiques (résumé PID + processus)
    - Tâches planifiées suspectes
    - Programmes au démarrage (autoruns registre + dossiers Démarrage)
    - Exclusions Windows Defender + règles ASR (Attack Surface Reduction)
    - Windows Hello (PIN/biométrie)
    - VBS / Credential Guard / Memory Integrity (HVCI) / LSA Protection (RunAsPPL)
    - Durcissement réseau (signature SMB, restrictions NTLM, DNS chiffré/DoH)
    - Smart App Control / WDAC
    - Certificats racine de confiance non standards + certificats expirés (Cert:\LocalMachine\My)
    - Shadow Copy / VSS (résistance ransomware)
    - Signatures Defender complémentaires (Antispyware + NIS)
    - Comparaison avec l'audit précédent (deltas de statut + évolution du score)
    - Alerte automatique si le score régresse de plus de $ScoreRegressionThreshold
      points depuis le dernier audit (bannière rouge dans le rapport HTML)
    - Historique multi-run (jusqu'à 20 derniers scores) avec mini-graphique
      d'évolution dans le rapport HTML
    - Score pondéré par catégorie + tableau détaillé par catégorie dans le rapport HTML
    - Bloc "Points critiques" en tête du rapport HTML
    - Rapport HTML généré automatiquement (recherche/filtre JS, ancres vers
      les contrôles critiques), export TXT, JSON et CSV
    - Protocoles TLS/SSL système et cipher suites faibles (SCHANNEL)
    - Filtre -Category pour n'exécuter que certaines sections
.PARAMETER Silent
    Supprime la sortie console, le prompt d'ouverture du navigateur et la
    pause ENTRÉE finale — utile pour une exécution via tâche planifiée. Les
    rapports HTML/TXT/JSON/CSV sont toujours générés normalement.
.PARAMETER Category
    Liste de catégories à exécuter. Si spécifié, seules les sections dont la
    catégorie principale correspond à un élément de la liste sont exécutées.
    Exemple : -Category "BitLocker","TLS/SCHANNEL"
    Valeurs possibles : Système, Mises à jour, Pare-feu, Antivirus, Comptes,
    UAC, BitLocker, Réseau, Services, Audit, Tâches planifiées, PowerShell,
    Logiciels, Démarrage, Defender, Windows Hello, VBS, Certificats,
    TLS/SCHANNEL, Sauvegarde, VSS
.NOTES
    Auteur  : Audit Sécurité Win11
    Version : 5.0.11
    Date    : 2026-08-19
    Exécuter en tant qu'Administrateur

    CHANGELOG v5.0.11 (2026-08-19) :

    - Correctif décalage du prompt "Ouvrir le rapport dans le navigateur ?" :
      la lettre tapée par l'utilisateur s'affichait sur la ligne au-dessus du
      prompt Read-Host. Cause : les émojis 📄/📝/🧩/📊 (chemins de rapports)
      et ✅/❌ (bannières SelfTest / AUDIT TERMINÉ) sont, comme ✔/⚠/✘/ℹ
      corrigés en v5.0.10, des glyphes à largeur ambiguë qui désynchronisent
      le calcul de position du curseur du terminal — l'effet ne se voyait pas
      sur ces lignes-là mais se répercutait sur le Read-Host suivant.
      Remplacés par les glyphes déjà validés « ✓ » et « » » (ce dernier
      repris du jeu d'icônes de Nettoyage-Windows11_v5_2).
    - Lisibilité console Section 10 (Journaux & Audit) : les lignes de
      politique d'audit (ex. "Politique : Connexion...") pouvaient dépasser
      700 caractères sur une seule ligne. Uniquement côté console (rendu de
      Write-Log) : au-delà de 90 caractères et présence du séparateur " / ",
      chaque sous-élément est maintenant replié sur sa propre ligne, indentée
      sous le séparateur "│", avec les espaces de padding internes (hérités
      de la sortie brute d'auditpol) resserrés à 2 espaces.
      $Value reste strictement inchangé pour TXT/HTML/JSON/CSV — seul le
      Write-Host est concerné, cf. principe "never break what works".

    CHANGELOG v5.0.10 (2026-08-19) :

    - Correctif rendu console suite retour utilisateur : icônes ✔ ⚠ ✘ ℹ
      collées au texte qui suit sur certaines polices Windows Terminal
      (glyphes à largeur "ambiguë" au sens Unicode East Asian Width, rendus
      en 2 cellules par certaines polices → l'espace suivant est absorbé
      visuellement). Remplacés côté console par ✓ ! ✗ · — le même jeu de
      glyphes déjà validé et utilisé dans Nettoyage-Windows11_v5_2 sur ce
      poste, garanti 1 cellule. Le rapport HTML n'est pas concerné : les
      icônes ✔ ✘ ⚠ ℹ de Get-StatusBadge restent inchangées (correctes dans
      un navigateur).
      Ajout d'une largeur de colonne fixe pour l'icône ($LogIconWidth = 2)
      afin que l'alignement du reste de la ligne (catégorie, séparateur │,
      valeur) reste garanti même si un glyphe s'affiche plus large que prévu
      sur une police donnée.

    CHANGELOG v5.0.9 (2026-08-19) :

    - Refonte esthétique de la sortie console (Write-Log / bannières SECTION)
      Aucun changement de logique de scoring ni de format du rapport TXT
      (Add-Content écrit toujours "[HH:mm:ss] [NIVEAU] message" à l'identique
      — compatibilité préservée avec tout parsing externe du .txt).
      Améliorations console uniquement :
        - Bannières de section encadrées (║ ... ║) avec numéro et titre,
          au lieu de simples lignes "=== N. TITRE ===".
        - Lignes de résultat (Add-Result) alignées en colonnes fixes :
          icône de statut, catégorie paddée, séparateur "│", contrôle,
          valeur colorée selon le statut (vert/jaune/rouge/cyan).
        - Icônes unifiées avec celles déjà utilisées dans le rapport HTML
          (✔ OK · ⚠ WARN · ✘ FAIL · ℹ INFO) au lieu de [OK]/[WARN]/[FAIL].
        - Timestamp en gris discret, catégorie en cyan, séparateurs en
          DarkGray pour réduire le bruit visuel et faire ressortir l'essentiel
          (le statut et la valeur).
        - Bannière finale de résumé harmonisée avec le même style encadré.
      Point de vigilance appliqué (cf. bug récurrent Dashboard-Global) :
      Write-Log garde exactement la même signature et le même comportement
      pour tout appel existant ($Message, -Level) ; les nouveaux paramètres
      (-Category/-Check/-Value) sont optionnels et n'affectent que le rendu
      console d'Add-Result, jamais le fichier TXT ni le retour de fonction.

    CHANGELOG v5.0.7 (2026-06-29) :

    - SECTION 4 — Refonte check scan Defender : quick scan + full scan distincts
      Ancien modèle : seul le full scan surveillé, seuils 7j WARN / 30j FAIL.
      Faux positif systématique sur NEPH-DESKTOP (full scan 11j → WARN) car
      Defender sur Win11 privilégie les quick scans automatiques quotidiens
      et ne lance pas de full scan spontanément.
      Nouveau modèle (deux contrôles) :
        Quick scan (indicateur principal) :
          >3j → WARN, >7j → FAIL, absent → WARN
          Signal fort : un quick scan absent = Defender perturbé
        Full scan (indicateur secondaire, seuils larges) :
          >30j → WARN, >90j → FAIL, jamais → INFO (non anomalie)
          Full scan mensuel recommandé mais non obligatoire



    CHANGELOG v5.0.6 (2026-06-29) :

    - SECTION 22 — Planification sauvegarde automatique wbadmin
      wbadmin get schedule n'est pas disponible sur Windows 11 Home
      (commande réservée à Windows Server). Sur Home, la planification
      est portée par la tâche planifiée :
        \Microsoft\Windows\WindowsBackup\AutomaticBackup
      On l'interroge via Get-ScheduledTask + Get-ScheduledTaskInfo pour
      extraire l'état (Ready/Running/Disabled/Absent), la fréquence du
      déclencheur, la prochaine exécution et la dernière exécution.
      Résultats :
        Ready/Running → OK  (planification active)
        Disabled      → WARN (plus de sauvegarde automatique)
        Tâche absente → INFO (sauvegarde manuelle uniquement)



    CHANGELOG v5.0.5 (hotfix post-run NEPH-DESKTOP 2026-06-29) :

    - SECTION 22 — Fix parsing wbadmin : champ "Durée de sauvegarde"
      La v5.0.4 cherchait "Heure de la sauvegarde" — champ inexistant sur
      locale FR. La sortie réelle de wbadmin sur NEPH-DESKTOP utilise :
        "Durée de sauvegarde : dd/MM/yyyy HH:mm"
        "Cible de sauvegarde : Disque dur étiqueté Auto_Save_Windows(E:)"
      Regex mis à jour pour couvrir "Durée de sauvegarde" (FR) et
      "Backup time" (EN). Parsing des dates via ParseExact dd/MM/yyyy HH:mm
      (InvariantCulture) pour éviter l'ambiguïté MM/dd vs dd/MM sur les
      dates dont le jour ≤ 12. Fallback sur Parse() si ParseExact échoue.
      Avec 9 sauvegardes sur E:\Auto_Save_Windows (13/05 → 28/06/2026),
      résultat attendu : OK "9 version(s) — dernière il y a 1 jour(s)".



    CHANGELOG v5.0.4 (2026-06-29) :

    - SECTION 22 — Ajout check sauvegarde image système wbadmin
      wbadmin get versions liste les sauvegardes complètes disponibles sur
      tous les volumes connectés (ex: E:\Auto_Save_Windows). On parse la
      date de la dernière version et le volume cible.
      Seuils : ≤30j → OK, 31-90j → WARN, >90j → FAIL, 0 version → INFO.
      Le check est indépendant du check VSS/shadow copies — les deux
      coexistent dans la section 22 : VSS couvre les points de restauration
      système, wbadmin couvre les images système complètes.



    CHANGELOG v5.0.3 (hotfix post-run NEPH-DESKTOP 2026-06-29) :

    - SECTION 22 — Faux FAIL VSS sur Win11 Home avec points de restauration
      Sur Windows 11 Home, vssadmin list shadows /for=C: retourne toujours 0
      résultat car les shadow copies VSS génériques ne sont pas créées
      automatiquement — seuls les POINTS DE RESTAURATION SYSTÈME existent.
      Ces derniers sont techniquement des shadow copies VSS mais cataloguées
      différemment (non listables via /for=C:). La v5.0.1 retournait donc FAIL
      systématiquement sur Win11 Home même si des points de restauration étaient
      présents.
      Nouvelle logique en trois niveaux :
      1. vssadmin retourne N blocs → traitement existant (OK/WARN par âge)
      2. vssadmin retourne 0 blocs → Get-ComputerRestorePoint en complément :
         - Points de restauration présents et récents (<30j) → OK
         - Points de restauration présents mais anciens (>30j) → WARN
      3. Ni shadow copy ni point de restauration → FAIL (cas réel)



    CHANGELOG v5.0.2 (hotfix post-run NEPH-DESKTOP 2026-06-29) :

    - SECTION 8 — Faux positif TCP public : pwsh signalé WARN
      PowerShell lui-même (pwsh) peut avoir une connexion TCP publique active
      au moment de l'audit — le script en cours d'exécution, une session PS
      ouverte en parallèle, ou une requête PSGallery/Update. Ajout de pwsh,
      powershell et powershell_ise à $SystemProcsAllowlist.
      Résultat attendu : Connexions TCP vers IPs publiques → INFO si seuls
      des processus reconnus sont présents.



    CHANGELOG v5.0.1 (hotfix post-run NEPH-DESKTOP 2026-06-29) :

    1. SECTION 8 — Faux positif connexions TCP vers IPs publiques
       NextDNSService, MpDefenderCoreService et Rainmeter signalés WARN car
       absents de $SystemProcsAllowlist. Tous légitimes :
       - NextDNSService : proxy DNS DoH local (NextDNS)
       - MpDefenderCoreService : composant cloud/telemetry de Defender
       - Rainmeter : widget bureau (trafic CDN météo/stats)
       Ajoutés à la liste blanche. Ajout préventif de NisSrv, SecurityHealthService,
       SgrmBroker, spoolsv, lsass, wininit (autres processus système attendus).

    2. SECTION 8 — Faux positif IPv6 : NotConfigured ≠ absence de blocage
       La v5.0 testait DefaultInboundAction -eq "Block" strictement. Sur Win11
       avec profil Public en configuration par défaut, la valeur est "NotConfigured"
       — Windows Defender Firewall applique quand même le blocage entrant par défaut.
       "NotConfigured" est maintenant accepté comme équivalent de "Block" → plus
       de WARN systématique sur tous les postes Win11 en configuration standard.

    3. SECTION 22 — Bug VSS : 0 shadow copy retournait INFO au lieu de FAIL
       vssadmin en français retourne un en-tête sans shadow copies qui ne
       matchait pas les patterns "Aucun élément trouvé" (accent manquant ou
       libellé différent selon la build). Nouvelle logique en deux passes :
       a) Compter les blocs "ID de cliché" AVANT de tenter le parsing des dates.
          0 blocs → FAIL direct, indépendamment du message d'en-tête.
       b) N blocs → parsing des dates pour affiner (OK/WARN selon l'âge).
          Parsing échoue mais N > 0 → INFO avec count (cas locale exotique).
       Ajout de "Snapshot ID" comme pattern alternatif anglais. Extraction des
       dates consolidée en un seul groupe ($_.Groups[1+2+3]) pour couvrir
       "Date et heure de création", "Creation Time" et "Date de création".

    CHANGELOG v5.0 (2026-06-29) :

    1. SECTION 5 — Compte Administrator intégré (RID-500)
       Vérifie explicitement si le compte Administrator (SID se terminant en -500)
       est activé. Sur un poste personnel, ce compte doit rester désactivé —
       son activation élargit la surface d'attaque brute-force locale.
       Résultat WARN si activé, INFO sinon. S'appuie sur Get-LocalUser filtré
       par SID -500 (universel, indépendant de la langue du système).

    2. SECTION 4 — Définitions Defender complémentaires (Antispyware + NIS)
       En plus de AntivirusSignatureLastUpdated, vérifie l'âge de :
       - AntispywareSignatureLastUpdated (module anti-spyware)
       - NISSignatureLastUpdated (Network Inspection System)
       Mêmes seuils que les signatures AV : >3j WARN, >7j FAIL.
       Ces deux composantes sont indépendantes de l'AV et peuvent dériver
       séparément si la mise à jour automatique est partiellement défaillante.

    3. SECTION 8 — IPv6 exposition pare-feu
       Vérifie si IPv6 est actif sur des interfaces non-loopback et si les
       profils de pare-feu couvrent explicitement IPv6. Un pare-feu Windows
       dont les règles d'entrée publiques sont toutes definies en IPv4 laisse
       un angle mort sur les interfaces IPv6 actives. WARN si IPv6 actif sans
       règles de blocage entrantes dédiées sur le profil Public.

    4. SECTION 8 — Connexions TCP vers IPs publiques (résumé par processus)
       Le résumé des connexions extérieures existait en INFO. En v5, on ajoute
       une passe de filtrage pour séparer les IPs RFC-1918 (privées) des IPs
       publiques, et produire un résumé "qui parle vers l'extérieur maintenant"
       avec le nom du processus. WARN si un processus inconnu (hors liste
       blanche système) établit des connexions vers des IPs publiques.

    5. SECTION 19 — Certificats expirés dans Cert:\LocalMachine\My
       Le magasin personnel machine peut accumuler des certificats expirés
       (anciens certificats de signature, certificats d'entreprise révoqués,
       etc.) qui ne sont pas supprimés automatiquement. Un certificat expiré
       dans ce magasin ne pose pas de risque de sécurité direct, mais signale
       une hygiène de PKI à améliorer. WARN si le magasin contient des certs
       expirés depuis plus de 365 jours, INFO en-deçà.

    6. SECTION 22 (NOUVELLE) — Shadow Copy / VSS
       Vérifie l'état du service VSS et l'existence de clichés instantanés
       récents sur C:. Un ransomware supprime systématiquement les shadow copies
       avant de chiffrer les fichiers — leur présence est un filet de sécurité.
       FAIL si aucun shadow copy, WARN si aucun dans les 7 derniers jours,
       OK si au moins un récent. Utilise vssadmin.exe (disponible sur toutes
       les éditions Windows 11 y compris Home).

    7. RAPPORT HTML — Tableau de score par catégorie
       Le rapport HTML expose désormais le détail du scoring par catégorie :
       un tableau "Catégorie | Score partiel | Poids | Contrôles" positionné
       sous la barre de score globale, permettant d'identifier immédiatement
       quelle catégorie tire le score vers le bas.

    8. RAPPORT HTML — Bloc "Points critiques" en tête de page
       Les contrôles FAIL et WARN les plus importants sont désormais affichés
       en tête du rapport (avant le tableau détaillé), dans un encadré rouge/
       orange visible immédiatement à l'ouverture du fichier.

    9. PARAMÈTRE -Category
       Filtre d'exécution : n'exécuter que les sections dont la catégorie
       principale correspond. Utile après un correctif ciblé (ex: après avoir
       activé BitLocker, relancer uniquement -Category "BitLocker") sans
       attendre les 3 minutes d'un audit complet.

   10. SELFTEST — Assertions étendues aux nouvelles sections (v5)
       Ajout d'assertions pour VSS (service lisible), Cert:\LocalMachine\My
       (magasin accessible), et le filtre -Category (liste non nulle si fournie).


    CHANGELOG v4.8.2 (hotfix post-revue ChatGPT 2026-06-28) :

    - TLS 1.2 WARN → INFO (faux positif confirmé).
      Sur Windows 11, TLS 1.2 est actif par défaut sans clé de registre —
      comportement stable et documenté Microsoft. WarnIfAbsent=$true générait
      un faux positif permanent sur tous les postes Win11 non configurés
      manuellement. Passé à WarnIfAbsent=$false : clé absente → INFO.
      Gain : -2 WARN → score attendu ~95/100.

    CHANGELOG v4.8.1 (hotfix post-run 2026-06-28) :

    - Bug chemin services non-système corrigé (section 9).
      Le nettoyage du PathName utilisait -replace ' .*$','' pour supprimer
      les arguments après l'exe, mais tronquait aussi "C:\Program Files\..."
      à "C:\Program" dès le premier espace → le match "program files" échouait
      toujours → NextDNSService, Windhawk et WSLService (tous dans Program Files)
      faussement classés "suspects" → WARN injustifié.
      Correction : si le PathName commence par un guillemet, extraire le chemin
      entre guillemets (préserve les espaces dans le nom de dossier). Sinon,
      couper au premier espace (cas sans guillemets, sans espaces dans le chemin).

    CHANGELOG v4.8 :

    1. SECTION 13 — Script Block Logging + Transcription PS → INFO
       Ces deux contrôles généraient des WARN permanents sur un poste perso.
       Script Block Logging et Transcription sont des outils de surveillance
       d'entreprise (enregistrement de tous les scripts dans les journaux /
       fichiers texte pour investigation forensique). Sur un poste Windows Home
       personnel bien géré (Defender actif, ASR, HVCI, LSA PPL, scripts
       signés), leur absence n'est pas une faiblesse — ils génèreraient du
       bruit inutile sans superviseur pour lire les logs. Downgradés en INFO
       avec message contextuel explicatif. Gain : -2 WARN permanents.

    2. SECTION 8 — Ports TCP en écoute : classification affinée par contexte
       L'ancienne version signalait WARN dès qu'un port sensible était en
       écoute, sans distinguer l'adresse locale. Or RPC 135 et SMB 445 sont
       présents sur toute machine Windows et écoutent sur des interfaces
       système internes — ce n'est pas la même chose que RDP 3389 exposé sur
       0.0.0.0. Nouvelle logique :
       - Port en écoute sur 0.0.0.0 ou :: (toutes interfaces) :
         RDP 3389 → FAIL (exposition directe)
         WinRM 5985/5986 → WARN fort
         Autres ports sensibles → WARN
       - Port en écoute sur une interface spécifique non-publique → INFO
       - RPC 135 et SMB 445 : INFO si uniquement sur interfaces système
         (comportement Windows normal), WARN si exposés sur 0.0.0.0.

    3. SECTION 13 — Smart App Control : distinguer non-compatible vs désactivé
       L'ancienne version affichait INFO dans tous les cas sauf état=1 (Actif).
       Sur un CPU non-compatible avec SAC (i7-7700HQ → Kaby Lake, antérieur
       à l'exigence SAC), "non disponible" est normal et mérite INFO.
       Sur un CPU compatible mais SAC désactivé définitivement (état=0), c'est
       un choix délibéré qui mérite INFO contextuel (pas un WARN — SAC peut
       bloquer des outils légitimes non signés et l'utilisateur a peut-être
       dû le désactiver pour cette raison).
       Sur un CPU compatible en mode évaluation (état=2), INFO avec conseil
       de laisser l'évaluation se terminer naturellement.

    CHANGELOG v4.7 :

    1. SECTION 2 — Dernier patch Windows > 30 jours → WARN (déjà en place,
       vérification confirmée : seuil 30j WARN / 60j FAIL déjà présent v1.x).
       Ajout du nombre de jours exact dans le message de détail.

    2. SECTION 4 — Dernier scan Defender > 7 jours → WARN
       L'ancienne version affichait juste la date sans niveau d'alerte sur
       l'ancienneté. Ajout d'un WARN si le scan date de plus de 7 jours et
       d'un FAIL si plus de 30 jours (scan vraiment négligé).

    3. SECTION 9 — Services auto non-système : afficher les noms + chemins
       Actuellement "3 services auto non-système" sans aucun détail. On affiche
       maintenant le nom, le DisplayName et le chemin de chaque service tiers
       en démarrage automatique dans le Detail du résultat. Le WARN se déclenche
       si un chemin est hors System32/Program Files (chemin suspect) ou si le
       compte de service n'est pas SYSTEM/LocalService/NetworkService.

    4. SECTION 16 — Exclusions Defender : afficher les valeurs dans le résumé
       Actuellement "1 exclusion de chemin" sans dire laquelle. Le chemin,
       l'extension et le processus exclus sont maintenant affichés directement
       dans la colonne Valeur du résultat (pas seulement dans le Detail).
       Le WARN sur les exclusions larges est conservé.

    5. SECTION 8 — Ports en écoute (Listen) enrichis avec PID/processus
       Nouvelle ligne listant les ports TCP en écoute sur des interfaces
       non-loopback avec le nom du processus associé. Complémentaire des
       connexions TCP établies. Alerte si un port sensible (RDP, WinRM,
       SMB, Telnet…) est en écoute sur une interface publique.

    6. RÉSUMÉ CONSOLE — détail FAIL/WARN dans le bandeau final
       Le bandeau `AUDIT TERMINÉ` affiche maintenant les contrôles FAIL et
       WARN (jusqu'à 5 de chaque) directement dans la console, pour un
       coup d'œil immédiat sans ouvrir le rapport HTML.

    CHANGELOG v4.6 :

    1. SECTION 4 — Historique Defender (détections 30 jours)
       Get-MpThreatDetection retourne la liste des menaces détectées et
       traitées par Windows Defender. 0 détection sur 30 jours = OK.
       Des détections récentes = INFO avec nom, action et date de chaque
       menace (max 10 affichées). Permet de savoir si Defender a neutralisé
       quelque chose en arrière-plan sans notification visible.
       Catégorie "Defender", poids 1.1 (déjà dans CategoryWeights).

    2. SECTION 3 — WARN "règles ouvertes à toute IP" downgradé en INFO
       Maintenant que la classification par éditeur (Microsoft/tiers/non signé)
       donne le détail actionnable, le comptage brut "31 règles ouvertes" ne
       faisait que dupliquer l'information en WARN sans valeur ajoutée.
       Downgradé en INFO — le WARN reste sur les catégories tiers/non signés
       qui sont les seules à nécessiter une attention.

    CHANGELOG v4.5 :

    1. ORDRE DES SECTIONS CORRIGÉ — section 21 s'affichait avant la 20.
       Permutation des blocs TLS (20) et Pilotes (21) pour restaurer
       l'ordre numérique correct 20 → 21 → RÉSUMÉ.

    2. PARE-FEU — Faux positifs "non signés" corrigés (section 3)
       a) Expansion des variables d'environnement avant Get-AuthenticodeSignature :
          %SystemRoot%\system32\svchost.exe → C:\Windows\System32\svchost.exe.
       b) Exécutables dans \Windows\System32\ et driver "System" → classés
          Microsoft directement sans vérification de signature.
       c) Règles "port seul" Microsoft (Microsoft Store, Pack d'expérience,
          Visionneuse web) → INFO au lieu de WARN.
       Résultat : 13 WARN → ~2 WARN réels (Snappy Driver Installer + tiers
       non signés), le reste reclassé INFO Microsoft.

    CHANGELOG v4.4.2 (hotfix post-run 2026-06-27) :

    - Faux positif WSL corrigé (section 21 — Pilotes récents, événement 7045).
      wslservice.exe dans "C:\Program Files\WSL\" signalé en WARN car hors
      System32\drivers et DriverStore. C'est un service officiel Microsoft
      (WSL) installé via Windows Update/Store — chemin légitime.
      Ajout de Program Files\WSL et Program Files\WindowsApps aux chemins
      de confiance. Les chemins AppData, Temp, ou utilisateur restent WARN.

    CHANGELOG v4.4.1 (hotfix post-run 2026-06-27) :

    - Faux positifs DEP/ASLR corrigés (section 13 — Exploit Protection).
      Get-ProcessMitigation retourne "NOTSET" quand une mitigation n'est pas
      configurée explicitement, pas "OFF". La v4.4 comparait à "ON" et
      interprétait NOTSET comme désactivé → 2 WARN injustifiés sur une machine
      où DEP et ASLR sont actifs par défaut (comportement Windows standard).
      Désormais : ON = OK, OFF = WARN, NOTSET = INFO (défaut Windows, sûr).
      Même logique que le traitement des clés TLS absentes.

    CHANGELOG v4.4 :

    1. SECTION 3 — Pare-feu : classification par éditeur/signature
       Les règles ouvertes à toute IP sont classées en 3 niveaux :
       Microsoft signé → INFO, tiers signé → WARN, non signé/inconnu → WARN fort.

    2. SECTION 7 — BitLocker : C: système = FAIL, autres volumes = WARN
       Les volumes non-système passent de FAIL à WARN (pertinent si données
       sensibles, non obligatoire pour un disque de jeux/technique).

    3. SECTION 13 — SmartScreen
       État de la protection SmartScreen (Off/Warn/RequireAdmin).
       RequireAdmin ou Warn = OK, Off = WARN.

    4. SECTION 13 — Exploit Protection (Process Mitigation Policies)
       Get-ProcessMitigation -System : vérifie DEP et ASLR au niveau système.

    5. SECTION 18 — Kernel-mode Hardware-enforced Stack Protection
       HVCIOptions bit 8 dans CI\Config — nécessite CPU Tiger Lake+/Zen 3+.

    6. SECTION 21 — Pilotes vulnérables (HVCI Blocklist + drivers récents)
       Nouvelle section : état de la blocklist Microsoft des drivers vulnérables
       + événement System 7045 (24h) pour les drivers installés hors circuit
       Windows Update (chemin hors System32/DriverStore).

    CHANGELOG v4.3.1 (hotfix) :

    - Bug $PID corrigé (section 8 — Connexions TCP).
      $PID est une variable réservée PowerShell (PID du processus courant),
      en lecture seule. Son utilisation dans un foreach levait silencieusement
      une erreur "Cannot overwrite variable PID because it is read-only",
      ce qui faisait tomber toute la section dans le catch → "Lecture
      impossible" en INFO à chaque run, même en admin.
      Renommé $pid → $procId dans la boucle d'enrichissement des connexions.
      Identifié via revue de rapport par ChatGPT (2026-06-27).

    CHANGELOG v4.3 :

    1. RAPPORT HTML — Colonne Δ inline dans le tableau de résultats
       Chaque ligne affiche une icône de variation dans la colonne Statut :
       - ▲ rouge : statut dégradé (ex: OK → FAIL)
       - ▼ vert  : statut amélioré (ex: WARN → OK)
       - ● gris  : nouveau contrôle absent du run précédent
       - (rien)  : statut inchangé
       $DeltaMap croisée lors de la génération des <tr>.

    2. MODE -SelfTest (31 assertions)
       Exécute une batterie de tests internes sans toucher au système ni
       générer de rapport. Assertions : He(), Get-StatusBadge, Add-Result,
       moteur de scoring pondéré, CategoryWeights (5 catégories vérifiées),
       ScoreRegressionThreshold, TrustedRootThumbprintAllowlist, TrustedTaskNames,
       logique BitLocker C:/non-C:, SmartScreen clé lisible, Get-ProcessMitigation
       disponible, CI\Config accessible, DeltaMap construction et lookup.
       Sortie : [PASS]/[FAIL] par assertion. Exit code 0 (tout OK) ou 1.

    CHANGELOG v4.2.1 (hotfix post-run 2026-06-27) :

    - Seuil WARN de l'événement 4648 relevé de 10 à 50.
      Après analyse des événements réels sur NEPH-DESKTOP : tous les 4648
      proviennent de svchost.exe / winlogon.exe / wininit.exe vers localhost
      (comptes DWM-1, UMFD-0/1, nephren) — bruit système normal généré au
      démarrage de session par les services de gestion de credentials Windows.
      Un seuil de 10 était trop bas pour ce poste et générait un WARN
      systématique sans valeur informative. 50 reste conservateur (un pic
      au-delà de 50 sur 24h mérite toujours investigation).

    CHANGELOG v4.2 :

    1. SECTION 8 — WinRM (Windows Remote Management)
       WinRM est le service d'accès distant PowerShell (WSMan). Actif = n'importe
       quel admin peut ouvrir une session PS distante sur la machine. Vérifie le
       statut du service WinRM ET la configuration du listener (port 5985/5986)
       via le registre WSMan. Service arrêté + pas de listener = OK. Service
       Running ou listener présent = WARN avec détail du port/transport.

    2. SECTION 10 — Événements de sécurité supplémentaires (24h)
       Trois nouvelles requêtes Get-WinEvent sur le journal Security :
       - ID 4648 : ouvertures de session avec credentials explicites (RunAs,
         net use /user, etc.) — signal d'élévation ou de mouvement latéral.
       - ID 4720 : création de compte utilisateur local.
       - ID 4726 : suppression de compte utilisateur local.
       Seuils : 0 = OK, 1-5 = INFO (peut être normal), >5 = WARN.

    3. SECTION 15 — IFEO hijacking + AppInit_DLLs
       - IFEO (Image File Execution Options) : sous-clés avec valeur "Debugger"
         permettent de substituer silencieusement un exe système à chaque
         lancement. Technique de persistance RAT classique.
       - AppInit_DLLs : DLL injectées dans tous les processus Win32 au boot.
         Doit être vide. Non vide = WARN immédiat.

    4. SECTION 8 — Profil réseau actif par interface
       Liste toutes les interfaces connectées avec leur profil (Public/Private/
       Domain) et le nom du réseau. WARN si profil Domain sur poste hors domaine
       (config orpheline potentiellement issue d'une migration ou d'une erreur).

    5. RAPPORT HTML — Résumé exécutif en tête de rapport
       Bloc "Points critiques" généré dynamiquement : FAIL en rouge, puis WARN,
       au-dessus du tableau. Limité à 10 éléments. Si tout est OK : bandeau vert.

    CHANGELOG v4.1 (correctifs post-run 2026-06-26) :

    1. REFONTE DU SCORING (bug critique hérité de v3.x, rendu apparent en v4.0)
       L'ancien modèle "100 − somme(malus)" était instable : chaque nouveau
       contrôle FAIL/WARN ajoutait du malus sans tenir compte du nombre total
       de contrôles. Exemple : 3 FAIL BitLocker × 10 × 1.6 = 48 pts de malus,
       + 6 WARN TLS × 3 × 1.4 = 25 pts → score = 1/100 sur une machine avec
       HVCI actif, LSA PPL UEFI, ASR 18 règles, Secure Boot, etc.
       
       Nouveau modèle : % de réussite pondéré par catégorie.
         Pour chaque catégorie C :
           - OK/INFO  = 1.0   (réussi)
           - WARN     = 0.5   (demi-réussite)
           - FAIL     = 0.0   (en défaut)
           taux_C = moyenne(valeurs statuts) sur tous les contrôles de C
         Score = Σ(poids_C × taux_C) / Σ(poids_C) × 100
       Propriétés :
         - Invariant au nombre de contrôles par catégorie.
         - Un FAIL BitLocker → catégorie BitLocker à 0%, sans impacter les autres.
         - Score 100 = tout OK. Score 0 = tout FAIL. Toujours entre 0 et 100.
         - Sur ce run (3 FAIL BitLocker, 6 WARN TLS, divers WARN) : ~84/100,
           ce qui reflète la réalité (bonne posture globale, BitLocker absent).
       Note : $CategoryWeights est conservé tel quel — les poids s'appliquent
       maintenant comme facteurs de pondération des catégories dans la moyenne,
       pas comme multiplicateurs de malus. La sémantique reste identique :
       BitLocker/Antivirus/VBS pèsent plus que Logiciels/Démarrage.

    2. CONNEXIONS TCP "WARN Lecture impossible" → "INFO"
       Get-NetTCPConnection peut lever une exception sur certains sockets
       système (héritage de session, ACL kernel) même en tant qu'admin.
       Ce n'est pas une anomalie de sécurité — l'erreur est maintenant
       capturée en INFO avec le message exact, et ne pénalise plus le score
       de la catégorie Réseau.

    CHANGELOG v4.0 :

    1. NOUVELLE SECTION 20 — Protocoles TLS/SSL et cipher suites (SCHANNEL)
       Lit les clés HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\
       SCHANNEL\Protocols\ pour vérifier que TLS 1.0 et TLS 1.1 sont bien
       désactivés (client ET serveur) et que TLS 1.2/1.3 sont activés.
       Clé absente = Windows applique ses défauts (permissif sur les vieilles
       builds) — traité en INFO avec le détail, pas silencieusement comme OK.
       Vérifie ensuite les cipher suites actives via
       HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\
       00010002\Functions pour signaler RC4, 3DES, DES, NULL, EXPORT si
       présents. Ce chemin n'existe QUE si une GPO ou une config manuelle a
       forcé une liste — son absence signifie que Windows gère les suites par
       défaut (INFO, pas un problème).
       Nouvelle catégorie "TLS/SCHANNEL" avec poids 1.4 dans $CategoryWeights.

    2. AMÉLIORATION SECTION 8 — Connexions TCP établies vers l'extérieur
       L'ancienne version (ajoutée en v1.x) affichait juste un comptage brut
       "Top 20 affichées dans le rapport" sans aucun enrichissement.
       Désormais chaque connexion est enrichie avec le nom du processus via
       Get-Process (croisement sur OwningProcess/Id), les adresses loopback
       et link-local IPv6 sont filtrées proprement, et les connexions dont
       le processus ne peut pas être résolu (accès refusé, PID disparu) sont
       signalées séparément. Les connexions orphelines (PID sans processus
       résolvable) génèrent un WARN — c'est le signe d'un processus qui
       s'est terminé juste après avoir établi la connexion, ou d'un socket
       maintenu par un service système non lisible.

    3. AMÉLIORATION SECTION RÉSUMÉ — Alerte régression de score
       Si le score baisse de plus de $ScoreRegressionThreshold points depuis
       le dernier audit, une bannière d'alerte distincte est affichée en
       console (Write-Log FAIL) et dans le rapport HTML (encadré rouge au
       dessus du bloc Évolution), indépendamment des deltas individuels.
       Configurable via $ScoreRegressionThreshold (défaut : 5 pts).
       Un delta de -1 ou -2 points sur un score de 98 n'est pas la même
       chose qu'une chute de 15 points — ce seuil évite les faux-positifs
       tout en alertant sur les régressions réelles.

    CHANGELOG v3.4 (analyse end-entity vs CA dans le magasin Root + allowlist
    du certificat GUID identifié) :
    - Constat suite à l'investigation du certificat CN=49793F74-...-4ED3A640FC76
      (WARN en v3.3) : l'analyse de ses extensions via PowerShell a révélé que
      c'est un certificat "Entité finale" (BasicConstraints : CA=FALSE), avec
      EKU Code Signing uniquement et des OIDs Microsoft 1.3.6.1.4.1.311.84.x
      (espace Microsoft Trusted Signing). Créé le 30/03/2026 par Windows lui-
      même pour la signature de packages MSIX/AppX locale. Non dangereux.
    - Ajouté à $TrustedRootThumbprintAllowlist avec une note explicite sur son
      type (end-entity, non CA), son EKU et son origine.
    - Nouveau : la section 19 détecte désormais si chaque certificat hors liste
      Microsoft est une CA (CA:TRUE dans BasicConstraints) ou une entité finale
      (CA:FALSE). Ce champ "Type" est affiché dans la fiche détail. La
      dangerosité estimée tient compte de cette distinction :
        - End-entity vérifié   → "Très faible (MITM impossible)"
        - End-entity non vérifié → "Modéré (MITM impossible mais placement
          dans Root non standard — identifier l'origine)"
        - CA non vérifiée       → "À examiner" ou "À examiner en priorité"
      Un end-entity dans Root ne peut pas signer d'autres certificats ni
      intercepter du TraficTLS, ce qui le rend fondamentalement moins risqué
      qu'une CA inconnue, même non vérifié.
    - Nouveau : l'EKU (Extended Key Usage) du certificat est également affiché
      dans la fiche détail — utile pour distinguer rapidement un cert de
      signature de code d'un cert TLS serveur ou d'une CA généraliste.

    CHANGELOG v3.3 (correction reconnaissance tâches planifiées personnelles) :
    - Constat : BloatRemoval, EdgeRemoval, OneDriveRemoval apparaissaient en
      WARN alors qu'il s'agit de tâches personnelles connues. Deux causes
      identifiées :
      1. La regex d'extraction de chemin [A-Za-z]:\\[^\s"]+\.ps1 exclut les
         espaces via [^\s] — elle s'arrête donc sur le premier espace d'un
         chemin comme "Scripts Maintenance Win11\Script.ps1" et échoue
         silencieusement, laissant $isTrusted à $false.
      2. Aucun filet de secours par nom de tâche : si le chemin n'était pas
         extractible (cmd inline, .bat, arguments sans .ps1 visible), la
         tâche finissait toujours dans $SuspTasksReal quelle que soit son
         origine.
    - Correction 1 : double tentative d'extraction du chemin — d'abord le
      pattern entre guillemets (gère les espaces : "([A-Za-z]:\\[^"]+\.ps1)")
      puis le pattern sans guillemets (inchangé pour les chemins sans espace).
      Premier match retenu.
    - Correction 2 : ajout de $TrustedTaskNames (CONFIGURATION) — allowlist
      par nom de tâche, vérifiée en priorité avant toute extraction de chemin.
      Indépendante du format des arguments, elle couvre tous les cas que la
      regex ne peut pas gérer. Pré-remplie avec BloatRemoval, EdgeRemoval,
      OneDriveRemoval.

    CHANGELOG v3.2 (liens d'aide contextuels) :
    - Nouveau : chaque contrôle en statut WARN ou FAIL affiche désormais,
      dans le rapport HTML, un ou plusieurs liens cliquables vers de la
      documentation ou un outil de diagnostic pertinent (essentiellement
      Microsoft Learn). Même principe que $script:RecoDb /
      Get-SourceRecommendation côté Analyze-WindowsLogs : une table de
      correspondance Catégorie + motif sur le nom du contrôle -> liens.
    - Deux cas traités hors table générique car le lien dépend de la valeur
      exacte du résultat, pas seulement de son type :
        - Certificats racine (section 19) : lien de recherche par EMPREINTE
          (crt.sh), pas par nom — cohérence avec le choix fait en v3.1
          (un nom de certificat est falsifiable, pas son empreinte).
        - Logiciels à surveiller (section 14) : lien de recherche CVE (NVD)
          construit sur le nom et la version exacts détectés.
    - Affiché uniquement sur WARN/FAIL — un contrôle OK/INFO n'a pas besoin
      de documentation de remédiation, ça aurait juste alourdi le tableau.
    - Ajout de la fonction He() (échappement HTML), absente jusqu'ici de ce
      script — nécessaire pour insérer des URLs/labels dans les attributs
      href sans risquer de casser le HTML sur un caractère spécial.
    - N'affecte pas les exports TXT/JSON/CSV (les liens sont une
      fonctionnalité du rapport HTML uniquement).

    CHANGELOG v3.1 (correction d'une faiblesse de conception dans la
    détection des certificats racine non standards, section 19) :
    - La v3.0 excluait un certificat de l'alerte en comparant son Subject CN
      à AuthRoot/aux noms de CA connues — or un Subject est une simple
      chaîne de texte non protégée cryptographiquement : un certificat
      malveillant peut se nommer "CN=DigiCert Trusted Root G4" sans rien
      prouver. Filtrer/exclure sur le nom aurait ouvert une voie de
      contournement triviale.
    - Remplacé par $TrustedRootThumbprintAllowlist (CONFIGURATION) : une
      allowlist indexée par EMPREINTE (thumbprint SHA-1), seule identité
      cryptographique non falsifiable d'un certificat. Le script ne déclasse
      un certificat en OK que si son empreinte exacte matche une entrée que
      tu as toi-même vérifiée et ajoutée à la liste — jamais sur la base du
      nom seul.
    - Aucune information n'est plus masquée : chaque certificat hors liste
      Microsoft (vérifié ou non) génère désormais une fiche complète — nom
      (CN, avec mention explicite si non descriptif/GUID), émetteur,
      emplacement du magasin, date d'expiration, empreinte, statut de
      légitimité calculé, et dangerosité estimée. Le nom reste affiché pour
      que tu puisses le reconnaître visuellement, mais sert uniquement
      d'indice de lisibilité dans le calcul de dangerosité, jamais de
      critère de confiance.
    - Allowlist initialisée avec les 3 empreintes confirmées légitimes lors
      de l'audit du 21/06/2026 (DigiCert Trusted Root G4, Thawte Timestamping
      CA, VeriSign Time Stamping Service Root) — le 4ᵉ certificat de ce
      run (CN par GUID) reste volontairement en WARN, non ajouté à la liste.

    CHANGELOG v3.0 (nouveaux contrôles de durcissement + refonte du scoring) :
    - Nouveau : LSA Protection (RunAsPPL) — protège lsass.exe contre le dump
      de credentials (Mimikatz et consorts). Ajouté section 18, à côté de
      Credential Guard puisque les deux ciblent la même menace.
    - Nouveau : règles ASR (Attack Surface Reduction) de Windows Defender,
      lues via Get-MpPreference (même cmdlet que les exclusions section 16) —
      compte les règles configurées et signale si aucune n'est active.
    - Nouveau : Smart App Control (Win11 22H2+), ajouté section 13 à côté
      d'AppLocker/ExecutionPolicy car même famille de contrôle d'applications.
    - Nouveau : durée de verrouillage de compte (LockoutDuration), en
      complément du seuil de verrouillage déjà présent section 5 — même appel
      ADSI, aucun coût supplémentaire.
    - Nouveau : signature SMB obligatoire (client + serveur) et restrictions
      NTLM (audit du niveau LmCompatibilityLevel, blocage NTLMv1), ajoutés
      section 8 à côté du contrôle SMBv1 déjà existant.
    - Nouveau : statut DNS chiffré (DoH) au niveau système, section 8 —
      cohérent avec un usage de résolveur DNS filtrant.
    - Nouveau : règles pare-feu entrantes "ouvertes à toute IP" désormais
      classées par dangerosité du port (RDP/SMB/WinRM/etc. signalés en FAIL,
      le reste en WARN), section 3 — auparavant un comptage brut sans
      distinction du risque réel par port.
    - Nouveau : section 19, certificats racine de confiance non standards
      dans le magasin LocalMachine\Root — un certificat ajouté hors de la
      liste Microsoft est un signe fréquent d'interception MITM ou de
      logiciel indésirable (proxy publicitaire, etc.).
    - Nouveau : vérification de la signature Authenticode du script
      lui-même au lancement (section 1) — cohérence avec l'usage de
      Sign-MyScripts.ps1 sur le reste de la suite.
    - Nouveau : score pondéré par catégorie au lieu d'un malus plat par
      statut. Les catégories à fort impact réel (BitLocker, Antivirus, VBS,
      Pare-feu, Réseau, LSA/Credential, Politique MDP) pèsent plus qu'un FAIL
      "Logiciel à surveiller" ou "Démarrage". Le détail du calcul est
      maintenant exposé dans le rapport (poids par catégorie en infobulle).
    - Nouveau : historique multi-run. En plus du baseline du dernier audit
      (_dernier_audit_baseline.json, conservé pour les deltas), un fichier
      d'historique (_historique_scores.json) conserve les 20 derniers
      (date, score) et alimente un mini-graphique SVG d'évolution dans le
      rapport HTML.
    - Nouveau : export CSV en plus de TXT/JSON/HTML, pour exploitation
      rapide dans Excel/LibreOffice.
    - Nouveau : recherche/filtre JavaScript dans le tableau du rapport HTML
      (même pattern que Block-Telemetry v5) — utile vu le volume de lignes
      des sections Logiciels/Démarrage.
    - Nouveau : liens d'ancrage en haut du rapport HTML vers les contrôles en
      statut FAIL, pour aller directement au problème sans scroller.
    - Tous les nouveaux contrôles registre/CIM suivent le pattern déjà établi
      dans la suite : try/catch systématique, jamais d'hypothèse sur la
      présence d'une clé ou d'une propriété, message INFO explicite en cas
      d'indisponibilité plutôt qu'un silence ou un faux OK/FAIL.

    CHANGELOG v2.3 (correction d'un crash dans le bloc deltas du rapport HTML) :
    - PowerShell 7+ convertit automatiquement les chaînes ISO-8601 (produites
      par "Get-Date -Format 'o'") en objets [DateTime] lors d'un
      ConvertFrom-Json — la baseline rechargée contenait donc un vrai
      [DateTime] et non une chaîne. Le code appelait .Substring() dessus en
      supposant une chaîne, d'où "Method invocation failed ... does not
      contain a method named 'Substring'" à la génération du rapport HTML.
      Remplacé par un formatage explicite qui gère les deux cas (DateTime ou
      string), avec repli sur l'affichage brut en cas d'échec de parsing.

    CHANGELOG v2.2 (alignement UX avec SpicyCheck-v7.0) :
    - Le rapport HTML n'est plus ouvert automatiquement à la fin : une
      question "Ouvrir le rapport dans le navigateur ? [O/n]" est posée
      (Entrée = Oui, comme dans SpicyCheck).
    - La fenêtre console ne se ferme plus automatiquement à la fin du
      script : un encadré "Appuyez sur ENTRÉE pour fermer cette fenêtre..."
      attend une validation avant la fin du script, pour laisser le temps de
      lire le résumé. Comportement sauté en mode -Silent, comme le reste de
      l'affichage console.

    CHANGELOG v2.1 (correction suite au run v2.0) :
    - Détection Windows Hello : le chemin utilisé
      (ServiceProfiles\LocalService\...\Ngc) est protégé par des ACL système
      et n'est lisible que par le compte SYSTEM, pas par un administrateur
      classique — l'ancienne version avalait silencieusement cette erreur
      d'accès et affichait à tort "Non détecté". Ajout d'un second chemin
      (conteneur NGC propre à l'utilisateur courant, accessible sans
      privilège particulier) et distinction explicite entre "non configuré"
      et "indéterminable faute d'accès", au lieu d'affirmer un résultat que
      le script n'a pas vraiment pu vérifier. Le message contextuel sur le
      flag SAM "mot de passe non requis" reflète maintenant ce 3ᵉ cas.

    CHANGELOG v2.0 (nouvelles fonctionnalités) :
    - Nouvelle section : programmes au démarrage (clés Registre Run/RunOnce
      HKLM+HKCU + dossiers Démarrage, raccourcis .lnk résolus). Heuristiques
      volontairement prudentes : seules les références à un fichier introuvable
      (orphelin) ou un lancement depuis un dossier Temp sont signalées — pas
      l'absence de signature seule, trop de logiciels légitimes n'étant pas
      signés pour que ce soit un signal fiable.
    - Nouvelle section : exclusions Windows Defender (chemins/extensions/
      processus). Seules les exclusions "larges" (racine de disque, dossier
      Windows/Users entier, wildcard générique) sont signalées en WARN — une
      exclusion ciblée et précise est normale et attendue.
    - Nouvelle section : détection Windows Hello (PIN/biométrie) au niveau
      machine. Réutilisée pour contextualiser le flag SAM "mot de passe non
      requis" en section Comptes (déjà adouci en v1.1) avec une explication
      concrète plutôt qu'une simple piste de vérification manuelle.
    - Nouvelle section : statut VBS (sécurité basée sur la virtualisation),
      Credential Guard et Memory Integrity (HVCI) via Win32_DeviceGuard.
    - Mode -Silent : supprime la sortie console et l'ouverture du navigateur,
      pour une exécution propre via tâche planifiée (rapports toujours générés).
    - Comparaison avec l'audit précédent : chaque exécution sauvegarde un
      fichier de référence (_dernier_audit_baseline.json). Au run suivant, le
      script calcule les changements de statut par contrôle (nouveau problème,
      résolu, contrôle apparu/disparu) et l'évolution du score, affichés en
      console et dans un nouveau bloc du rapport HTML.
    - Export JSON complet du run courant (machine, score, résumé, tous les
      résultats détaillés, deltas) en plus du HTML/TXT, pour exploitation par
      d'autres scripts/outils.

    CHANGELOG v1.3 (clarifications suite aux retours du run v1.2) :
    - Politique de mot de passe (longueur minimale) : ce contrôle lit la
      politique LOCALE (ce que Windows imposerait pour un futur changement de
      mot de passe), pas le mot de passe réellement utilisé pour ouvrir la
      session. Un "0 caractère" ne veut pas dire que le compte n'a pas de mot
      de passe. Libellé et message clarifiés, sévérité ramenée de FAIL à WARN
      (ce n'est pas une brèche active, juste une politique permissive).
    - Service Windows Update (section Services) : un service en démarrage
      Manuel (wuauserv, par conception sur Windows moderne) est normalement
      arrêté hors utilisation — ce n'était pas une anomalie. Seul un service
      Disabled, ou un service Automatic non démarré, est désormais signalé
      comme un vrai problème.
    - Logiciels "sensibles" (VLC, 7-Zip, etc.) : le script ne vérifie aucune
      base de CVE ni la dernière version publiée, donc il ne peut pas savoir
      si l'installation est vulnérable — repassé en INFO (liste de
      surveillance) au lieu de WARN, pour ne plus signaler à tort un logiciel
      à jour comme un problème.

    CHANGELOG v1.2 (suite aux résultats du run v1.1) :
    - Politique de mot de passe : le correctif ADSI v1.1 liait l'objet sans
      suffixe de classe, ce qui résout par défaut à la classe COM "Computer"
      (sans les propriétés de politique de mot de passe) au lieu de "Domain"
      -> erreur "Object reference not set". Liaison corrigée en
      "WinNT://COMPUTERNAME,Domain" + reconstruction manuelle de
      MaxPasswordAge (IADsLargeInteger, HighPart/LowPart).

    CHANGELOG v1.1 (corrections de faux positifs / bugs) :
    - Politique de mot de passe : lecture via ADSI (WinNT provider) au lieu du
      parsing texte de "net accounts", qui échouait sur un Windows en français
      (chaînes anglaises non trouvées -> erreur de cast).
    - Politique d'audit : interrogation d'auditpol par GUID de catégorie
      (indépendant de la langue) au lieu du nom anglais de catégorie, et parsing
      structurel (par position de ligne) au lieu d'un filtre regex anglais.
    - Membres du groupe Administrateurs : lecture par SID universel
      (S-1-5-32-544) au lieu du nom localisé "Administrators", avec remontée
      explicite d'une erreur si la lecture échoue (au lieu d'un "OK" silencieux
      sur une valeur vide).
    - AMSI : si la propriété AMSIEnabled n'est pas exposée par Get-MpComputerStatus
      sur la build en cours, le contrôle passe en INFO au lieu de WARN (au lieu
      d'interpréter une valeur absente comme "désactivé").
    - Compte sans mot de passe requis (flag SAM) : statut ramené de FAIL à WARN
      avec une note explicative, ce flag pouvant être positionné par Windows
      Hello (PIN/biométrie) sans rapport avec un vrai défaut de sécurité.
    - Tâches planifiées suspectes : exclusion automatique des tâches dont le
      script est signé par le certificat personnel de l'auteur, ou dont le
      chemin correspond à une liste de dossiers de confiance configurable.
    - Pare-feu : distinction entre "règles actives sur le profil Public"
      (informatif, inclut les règles scopées par programme) et "règles
      réellement ouvertes à n'importe quelle adresse distante" (le vrai risque).
    - BitLocker : message contextualisé selon que le volume est le volume
      système ou un volume de données.
    - Remplacement de Get-WmiObject (absent de PowerShell 7+) par
      Get-CimInstance pour la détection des services suspects.
    - Dernier scan Defender complet : statut explicite si aucun scan complet
      n'a jamais été exécuté, au lieu d'un champ vide non interprété.
#>

param(
    [switch]$Silent,
    [switch]$SelfTest,
    [string[]]$Category = @()
)

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────
$ScriptVersion  = "5.0.11"
$ReportDate     = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportName     = "Audit_Securite_Win11_$ReportDate"
$OutputDir      = "$env:USERPROFILE\Desktop\Rapports_Maintenance\AuditSecurity"
$ReportHTML     = "$OutputDir\$ReportName.html"
$ReportTXT      = "$OutputDir\$ReportName.txt"
$ReportJSON     = "$OutputDir\$ReportName.json"
$ReportCSV      = "$OutputDir\$ReportName.csv"
# Fichier de référence du run précédent, utilisé pour calculer les deltas
# (écrasé à chaque exécution avec les résultats du run courant).
$BaselineFile   = "$OutputDir\_dernier_audit_baseline.json"
# NOTE v3.0 : fichier d'historique multi-run, distinct du baseline ci-dessus.
# Le baseline ne garde que le run précédent (nécessaire aux deltas). Celui-ci
# accumule (date, score) sur les 20 derniers runs pour tracer une mini-courbe
# d'évolution dans le rapport HTML — le baseline seul ne le permettait pas.
$HistoryFile    = "$OutputDir\_historique_scores.json"
$MaxHistoryRuns = 20

# NOTE v4.0 : seuil de régression du score (en points) au-delà duquel une
# alerte distincte est émise en console et dans le rapport HTML. Un delta de
# -1 ou -2 pts sur un score de 98 n'est pas significatif ; une chute de 5+
# pts signale une dégradation réelle qui mérite une attention immédiate.
# Mettre à 0 pour alerter sur tout recul, même minime (non recommandé).
$ScoreRegressionThreshold = 5

# NOTE v3.0 : poids par catégorie pour le calcul du score (voir section
# RÉSUMÉ plus bas). Un FAIL sur une catégorie à fort impact réel (BitLocker,
# Antivirus, VBS, etc.) doit peser plus qu'un FAIL sur une catégorie purement
# informative ("Logiciels à surveiller", "Démarrage"). Catégorie absente de
# cette table = poids par défaut 1.0 (ni amplifié ni atténué).
$CategoryWeights = @{
    "Antivirus"      = 1.6
    "Pare-feu"       = 1.4
    "Réseau"         = 1.4
    "BitLocker"      = 1.6
    "VBS"            = 1.5
    "Politique MDP"  = 1.3
    "Comptes"        = 1.2
    "Durcissement"   = 1.4
    "Certificats"    = 1.3
    "Defender"       = 1.1
    "Logiciels"      = 0.5
    "Démarrage"      = 0.7
    "Services"       = 0.8
    "TLS/SCHANNEL"   = 1.4
    "Sauvegarde"     = 1.5
}

# NOTE v5.0 : table de correspondance section → catégories principales, utilisée
# par le filtre -Category. Chaque entrée indique les catégories de résultats
# qu'une section produit. Si -Category est vide, toutes les sections s'exécutent.
$SectionCategoryMap = @{
    "1_Systeme"         = @("Système")
    "2_Updates"         = @("Mises à jour")
    "3_Parefeu"         = @("Pare-feu")
    "4_Defender"        = @("Antivirus","Defender")
    "5_Comptes"         = @("Comptes","Politique MDP")
    "6_UAC"             = @("UAC")
    "7_BitLocker"       = @("BitLocker")
    "8_Reseau"          = @("Réseau")
    "9_Services"        = @("Services")
    "10_Audit"          = @("Audit")
    "11_Taches"         = @("Tâches planifiées")
    "12_Securite_UEFI"  = @("Sécurité UEFI")
    "13_PowerShell"     = @("PowerShell")
    "14_Logiciels"      = @("Logiciels")
    "15_Demarrage"      = @("Démarrage")
    "16_Exclusions"     = @("Defender")
    "17_Hello"          = @("Windows Hello")
    "18_VBS"            = @("VBS")
    "19_Certificats"    = @("Certificats")
    "20_TLS"            = @("TLS/SCHANNEL")
    "21_Pilotes"        = @("Démarrage")
    "22_VSS"            = @("Sauvegarde")
}

# Fonction utilitaire : détermine si une section doit être exécutée selon -Category
function ShouldRunSection {
    param([string]$SectionKey)
    if ($Category.Count -eq 0) { return $true }
    if (-not $SectionCategoryMap.ContainsKey($SectionKey)) { return $true }
    foreach ($cat in $SectionCategoryMap[$SectionKey]) {
        foreach ($filter in $Category) {
            if ($cat -like "*$filter*" -or $filter -like "*$cat*") { return $true }
        }
    }
    return $false
}

# NOTE v3.1 : allowlist de certificats racine légitimes, indexée par EMPREINTE
# (thumbprint SHA-1), pas par nom. Le Subject CN d'un certificat est une
# simple chaîne de texte — n'importe quel certificat auto-signé peut se faire
# appeler "CN=DigiCert Trusted Root G4", donc filtrer sur le nom serait
# contournable trivialement par un certificat malveillant qui copierait le
# nom d'une CA connue. L'empreinte, elle, est une signature cryptographique
# du certificat exact : impossible à falsifier sans casser SHA-1/SHA-256.
# Ajoute ici uniquement des empreintes que TU as toi-même vérifiées (vues
# dans un rapport d'audit, confirmées légitimes). Le script ne fait AUCUNE
# confiance automatique sur la base du nom — voir section 19.
$TrustedRootThumbprintAllowlist = @{
    # Vérifiées le 21/06/2026 suite à l'audit Audit_Securite_Win11_2026-06-21_20-35-02 :
    "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4" = "DigiCert Trusted Root G4 — CA commerciale majeure largement déployée"
    "BE36A4562FB2EE05DBB3D32323ADF445084ED656" = "Thawte Timestamping CA — CA d'horodatage legacy, expirée mais volontairement conservée par Windows pour valider la date de signatures anciennes"
    "18F7C1FCC3090203FD5BAA2F861A754976C8DD25" = "VeriSign Time Stamping Service Root — idem, CA d'horodatage legacy expirée et volontairement conservée"
    # Vérifié le 22/06/2026 via analyse des extensions (certutil + PowerShell) :
    # - BasicConstraints : End Entity (pas une CA — ne peut PAS signer d'autres certs ni faire du MITM)
    # - EKU : Code Signing uniquement + OIDs Microsoft 1.3.6.1.4.1.311.84.3.1/.3.2 (Microsoft Trusted Signing)
    # - Créé le 30/03/2026 par Windows lui-même (mise à jour ou install Microsoft Store)
    # - Inhabituellement placé dans Root plutôt que dans le magasin personnel, mais non dangereux
    "899B104B6A3EE5AC8E3884A036BD946609F54B43" = "Certificat Windows Trusted Signing (end-entity, non CA) — créé par Windows le 30/03/2026 pour signature de packages MSIX/AppX locale ; OIDs Microsoft 311.84.x confirmés"
}

# Dossiers considérés comme tiens (tes propres scripts planifiés) — à adapter.
# Toute tâche planifiée dont le script se trouve sous un de ces chemins ne sera
# pas comptée comme suspecte. Complète également $TrustedSignerSubjectMatch
# plus bas si tu signes tes scripts avec un certificat personnel.
$TrustedScriptPathPatterns = @(
    "$env:USERPROFILE\Desktop\*",
    "$env:USERPROFILE\Documents\*",
    "$env:USERPROFILE\Scripts\*"
)
$TrustedSignerSubjectMatch = "Erwan"

# NOTE v3.3 : allowlist par NOM de tâche — filet de secours indépendant du
# format des arguments de la tâche. Utilisé quand la tâche ne contient pas
# de chemin .ps1 extractible (cmd inline, .bat, arguments sans chemin
# explicite, etc.) ou quand le chemin a des espaces que l'ancienne regex
# ne capturait pas. À compléter avec tes propres tâches planifiées.
$TrustedTaskNames = @(
    "BloatRemoval",
    "EdgeRemoval",
    "OneDriveRemoval"
)

# Créer le dossier de sortie
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Charger le résultat du run précédent (pour la section "Évolution" plus bas).
# Si le fichier est absent ou corrompu, on continue simplement sans comparaison.
$PreviousAudit = $null
if (Test-Path $BaselineFile) {
    try {
        $PreviousAudit = Get-Content -Path $BaselineFile -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        $PreviousAudit = $null
    }
}

# NOTE v3.0 : historique multi-run (distinct du baseline) pour le
# mini-graphique d'évolution du score dans le rapport HTML. Même tolérance
# de panne que le baseline : fichier absent ou corrompu -> on repart d'une
# liste vide plutôt que de planter le script.
$ScoreHistory = [System.Collections.Generic.List[object]]::new()
if (Test-Path $HistoryFile) {
    try {
        $LoadedHistory = Get-Content -Path $HistoryFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($h in @($LoadedHistory)) { $ScoreHistory.Add($h) }
    } catch {
        $ScoreHistory = [System.Collections.Generic.List[object]]::new()
    }
}

# ──────────────────────────────────────────────
#  FONCTIONS UTILITAIRES
# ──────────────────────────────────────────────

# NOTE v5.0.9 : largeur de la colonne "catégorie" pour l'alignement console.
# Calculée sur la plus longue catégorie réellement utilisée par Add-Result
# ("Tâches planifiées" = 18 car.) + marge. Une catégorie plus longue ne casse
# rien : PadRight n'agit que si la chaîne est plus courte que la largeur.
$script:LogCategoryWidth = 20

# NOTE v5.0.10 : icônes console — REVU après retour utilisateur (icône collée
# au texte sur certaines polices Windows Terminal). Cause : ✔ ⚠ ✘ ℹ sont des
# glyphes à largeur "ambiguë" (Unicode East Asian Width), rendus en 2 cellules
# par certaines polices → l'espace qui suit est visuellement absorbé.
# Remplacés par les glyphes déjà validés dans Nettoyage-Windows11_v5_2 sur ce
# même poste (✓ ~ ! - · » ≈), qui s'affichent correctement en 1 cellule.
# Ces icônes console sont indépendantes de celles du rapport HTML
# (Get-StatusBadge garde ✔ ✘ ⚠ ℹ, corrects dans un navigateur).
$script:LogIcons = @{ "OK"="✓"; "WARN"="!"; "FAIL"="✗"; "INFO"="·" }
# Largeur de colonne fixe pour l'icône (2 caractères) : garantit un
# alignement stable même si un glyphe donné s'affiche plus large que prévu
# sur une police donnée — le texte qui suit démarre toujours à la même colonne.
$script:LogIconWidth = 2

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        # Paramètres optionnels v5.0.9 — utilisés uniquement par Add-Result
        # pour un rendu console en colonnes alignées. Sans impact sur le
        # comportement existant : un appel Write-Log "texte" -Level X rend
        # exactement comme avant (hors alignement), et le fichier TXT n'est
        # dans tous les cas jamais généré à partir de ces paramètres.
        [string]$Category = "",
        [string]$Check = "",
        [string]$Value = ""
    )
    $timestamp = Get-Date -Format "HH:mm:ss"
    $colors = @{ "INFO"="Cyan"; "OK"="Green"; "WARN"="Yellow"; "FAIL"="Red"; "SECTION"="Magenta" }
    $color = $colors[$Level]

    # NOTE v2.0 : en mode -Silent (exécution planifiée/headless), on n'écrit
    # plus dans la console — le fichier TXT reste alimenté dans tous les cas.
    if (-not $Silent) {
        if ($Level -eq "SECTION") {
            # Bannière de section encadrée. On extrait "N. TITRE" depuis
            # "=== N. TITRE ===" pour un rendu propre sans dépendre du format
            # d'origine (fallback : affiche le message brut si le motif ne
            # correspond pas, ex. "=== RÉSUMÉ ===").
            $title = ($Message -replace '^\s*=+\s*', '') -replace '\s*=+\s*$', ''
            $barWidth = 62
            Write-Host ""
            Write-Host ("  ╔" + ("═" * $barWidth) + "╗") -ForegroundColor DarkCyan
            $titlePadded = " $title".PadRight($barWidth)
            Write-Host "  ║" -NoNewline -ForegroundColor DarkCyan
            Write-Host $titlePadded -NoNewline -ForegroundColor Cyan
            Write-Host "║" -ForegroundColor DarkCyan
            Write-Host ("  ╚" + ("═" * $barWidth) + "╝") -ForegroundColor DarkCyan
        }
        elseif ($Category) {
            # Ligne de résultat alignée : heure · icône · catégorie · contrôle · valeur
            $icon = $script:LogIcons[$Level]
            if (-not $icon) { $icon = "•" }
            $iconCol = $icon.PadRight($script:LogIconWidth)
            $catCol = $Category.PadRight($script:LogCategoryWidth)
            # Chaîne "à plat" (non colorée) servant uniquement à calculer la
            # largeur d'indentation des lignes de repli ci-dessous.
            $plainPrefix = "   $timestamp  $iconCol $catCol"

            # NOTE v5.0.11 : certaines valeurs (ex. politique d'audit, Section 10)
            # concatènent de nombreux sous-éléments avec " / " et dépassent
            # largement la largeur d'une console (plusieurs centaines de
            # caractères sur une seule ligne, illisible). On ne touche pas au
            # format sous-jacent ($Value reste inchangé pour TXT/HTML/JSON/CSV,
            # cf. Add-Result) — uniquement la présentation console : au-delà
            # d'un certain seuil, on replie chaque sous-élément sur sa propre
            # ligne, indentée sous le séparateur "│".
            if ($Value -match ' / ' -and $Value.Length -gt 90) {
                Write-Host "   $timestamp  " -NoNewline -ForegroundColor DarkGray
                Write-Host "$iconCol " -NoNewline -ForegroundColor $color
                Write-Host "$catCol" -NoNewline -ForegroundColor DarkCyan
                Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                Write-Host "$Check" -ForegroundColor Gray
                $indent = " " * $plainPrefix.Length
                foreach ($item in ($Value -split ' / ')) {
                    $item = $item.Trim()
                    if (-not $item) { continue }
                    # Les lignes brutes d'auditpol contiennent un padding large
                    # entre le nom et le réglage (ex. "Ouvrir la session" +
                    # 20+ espaces + "Succès et échec") ; on le resserre à 2
                    # espaces pour un rendu console compact et lisible, sans
                    # toucher au $Value original (TXT/HTML/JSON/CSV inchangés).
                    $item = $item -replace '\s{2,}', '  '
                    Write-Host "$indent" -NoNewline
                    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$item" -ForegroundColor $color
                }
            }
            else {
                Write-Host "   $timestamp  " -NoNewline -ForegroundColor DarkGray
                Write-Host "$iconCol " -NoNewline -ForegroundColor $color
                Write-Host "$catCol" -NoNewline -ForegroundColor DarkCyan
                Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                Write-Host "$Check" -NoNewline -ForegroundColor Gray
                Write-Host " : " -NoNewline -ForegroundColor DarkGray
                Write-Host "$Value" -ForegroundColor $color
            }
        }
        else {
            # Message libre (résumé, erreurs, alertes) — icône + couleur,
            # sans colonne de catégorie puisqu'il n'y en a pas.
            $icon = $script:LogIcons[$Level]
            if (-not $icon) { $icon = "•" }
            $iconCol = $icon.PadRight($script:LogIconWidth)
            Write-Host "   $timestamp  " -NoNewline -ForegroundColor DarkGray
            Write-Host "$iconCol " -NoNewline -ForegroundColor $color
            Write-Host "$Message" -ForegroundColor $color
        }
    }
    # Le fichier TXT garde STRICTEMENT le format d'origine, quel que soit le
    # rendu console — ne jamais faire dépendre un export/parsing externe
    # (Dashboard-Global ou autre) d'un changement purement cosmétique.
    Add-Content -Path $ReportTXT -Value "[$timestamp] [$Level] $Message"
}

function Get-StatusBadge {
    param([string]$Status)
    switch ($Status) {
        "OK"   { return '<span class="badge ok">✔ OK</span>' }
        "WARN" { return '<span class="badge warn">⚠ ATTENTION</span>' }
        "FAIL" { return '<span class="badge fail">✘ CRITIQUE</span>' }
        "INFO" { return '<span class="badge info">ℹ INFO</span>' }
        default { return '<span class="badge info">— N/A</span>' }
    }
}

# NOTE v3.2 : échappement HTML natif, même pattern que He() dans
# Analyze-WindowsLogs ([System.Web.HttpUtility]::HtmlEncode() n'est pas
# garanti disponible dans tous les contextes PowerShell — voir le
# changelog historique de la suite).
function He {
    param([string]$s)
    if ($null -eq $s) { return "" }
    $s = $s -replace '&','&amp;'; $s = $s -replace '<','&lt;'
    $s = $s -replace '>','&gt;';  $s = $s -replace '"','&quot;'
    $s = $s -replace "'","&#39;"; return $s
}

# ──────────────────────────────────────────────
#  MOTEUR DE LIENS D'AIDE CONTEXTUELS (v3.2 NEW)
# ──────────────────────────────────────────────
# NOTE v3.2 : même principe que $script:RecoDb / Get-SourceRecommendation
# dans Analyze-WindowsLogs — une table de correspondance Catégorie/Contrôle
# -> liens cliquables (documentation Microsoft Learn, outils, recherches),
# affichée uniquement sur les contrôles WARN/FAIL dans le rapport HTML pour
# ne pas alourdir les lignes OK/INFO. Chaque règle matche sur la catégorie
# ET un motif (regex) appliqué au nom du contrôle — premier match retenu.
$script:HelpLinksDb = @(
    @{ Cat='BitLocker';     Pattern='Volume';                    Links=@(
        @{ Label='MS Learn : Activer BitLocker';   Url='https://learn.microsoft.com/fr-fr/windows/security/operating-system-security/data-protection/bitlocker/' }
        @{ Label='MS Learn : BitLocker FAQ';        Url='https://learn.microsoft.com/fr-fr/windows/security/operating-system-security/data-protection/bitlocker/faq' }
    )}
    @{ Cat='VBS';            Pattern='LSA Protection';            Links=@(
        @{ Label='MS Learn : Configurer LSA Protection'; Url='https://learn.microsoft.com/fr-fr/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection' }
    )}
    @{ Cat='VBS';            Pattern='Memory Integrity|virtualisation';  Links=@(
        @{ Label='MS Learn : Memory Integrity (HVCI)'; Url='https://learn.microsoft.com/fr-fr/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity' }
    )}
    @{ Cat='VBS';            Pattern='Credential Guard';          Links=@(
        @{ Label='MS Learn : Credential Guard'; Url='https://learn.microsoft.com/fr-fr/windows/security/identity-protection/credential-guard/' }
    )}
    @{ Cat='Antivirus';      Pattern='ASR|Attack Surface';        Links=@(
        @{ Label='MS Learn : Référence des règles ASR'; Url='https://learn.microsoft.com/fr-fr/defender-endpoint/attack-surface-reduction-rules-reference' }
    )}
    @{ Cat='Antivirus';      Pattern='.*';                        Links=@(
        @{ Label='MS Learn : Dépannage Windows Defender'; Url='https://learn.microsoft.com/fr-fr/defender-endpoint/troubleshoot-microsoft-defender-antivirus' }
    )}
    @{ Cat='PowerShell';     Pattern='Smart App Control';         Links=@(
        @{ Label='MS Learn : Smart App Control'; Url='https://learn.microsoft.com/fr-fr/windows/apps/develop/smart-app-control/overview' }
    )}
    @{ Cat='PowerShell';     Pattern='Script Block Logging|Transcription'; Links=@(
        @{ Label='MS Learn : Journalisation PowerShell'; Url='https://learn.microsoft.com/fr-fr/powershell/module/microsoft.powershell.core/about/about_logging_windows' }
    )}
    @{ Cat='PowerShell';     Pattern='ExecutionPolicy';           Links=@(
        @{ Label='MS Learn : about_Execution_Policies'; Url='https://learn.microsoft.com/fr-fr/powershell/module/microsoft.powershell.core/about/about_execution_policies' }
    )}
    @{ Cat='TLS/SCHANNEL';   Pattern='TLS 1\.0|TLS 1\.1|SSL';              Links=@(
        @{ Label='MS Learn : Désactiver TLS 1.0 et 1.1';  Url='https://learn.microsoft.com/fr-fr/windows-server/security/tls/tls-registry-settings' }
        @{ Label='MS Learn : Paramètres registre SCHANNEL'; Url='https://learn.microsoft.com/fr-fr/windows-server/security/tls/tls-registry-settings' }
    )}
    @{ Cat='TLS/SCHANNEL';   Pattern='Cipher|suite';                       Links=@(
        @{ Label='MS Learn : Cipher suites TLS Windows';   Url='https://learn.microsoft.com/fr-fr/windows/win32/secauthn/cipher-suites-in-schannel' }
        @{ Label='MS Learn : Gérer les protocoles TLS';    Url='https://learn.microsoft.com/fr-fr/windows-server/security/tls/manage-tls' }
    )}
    @{ Cat='TLS/SCHANNEL';   Pattern='.*';                                 Links=@(
        @{ Label='MS Learn : Vue d''ensemble TLS/SSL (SCHANNEL)'; Url='https://learn.microsoft.com/fr-fr/windows-server/security/tls/tls-ssl-schannel-ssp-overview' }
    )}
    @{ Cat='Réseau';         Pattern='WinRM|accès PS distant';           Links=@(
        @{ Label='MS Learn : Désactiver WinRM';            Url='https://learn.microsoft.com/fr-fr/windows/win32/winrm/installation-and-configuration-for-windows-remote-management' }
    )}
    @{ Cat='Réseau';         Pattern='Restriction NTLM|LmCompatibilityLevel'; Links=@(        @{ Label='MS Learn : Niveau authentification LAN Manager'; Url='https://learn.microsoft.com/fr-fr/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level' }
    )}
    @{ Cat='Réseau';         Pattern='Signature SMB';             Links=@(
        @{ Label='MS Learn : Signature SMB'; Url='https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/networking/overview-server-message-block-signing' }
    )}
    @{ Cat='Réseau';         Pattern='SMBv1';                     Links=@(
        @{ Label='MS Learn : Désactiver SMBv1'; Url='https://learn.microsoft.com/fr-fr/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3' }
    )}
    @{ Cat='Réseau';         Pattern='DNS chiffré|DoH';           Links=@(
        @{ Label='MS Learn : DNS-over-HTTPS sur Windows'; Url='https://learn.microsoft.com/fr-fr/windows-server/networking/dns/doh-client-support' }
    )}
    @{ Cat='Réseau';         Pattern='NLA|RDP';                   Links=@(
        @{ Label='MS Learn : Sécuriser les connexions RDP'; Url='https://learn.microsoft.com/fr-fr/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access' }
    )}
    @{ Cat='Réseau';         Pattern='Partages réseau';           Links=@(
        @{ Label='MS Learn : Sécurité des partages SMB'; Url='https://learn.microsoft.com/fr-fr/windows-server/storage/file-server/smb-security' }
    )}
    @{ Cat='Pare-feu';       Pattern='Port sensible';             Links=@(
        @{ Label='MS Learn : Pare-feu Windows Defender, bonnes pratiques'; Url='https://learn.microsoft.com/fr-fr/windows/security/operating-system-security/network-security/windows-firewall/best-practices-configuring' }
    )}
    @{ Cat='Pare-feu';       Pattern='.*';                        Links=@(
        @{ Label='MS Learn : Pare-feu Windows Defender'; Url='https://learn.microsoft.com/fr-fr/windows/security/operating-system-security/network-security/windows-firewall/' }
    )}
    @{ Cat='Politique MDP';  Pattern='.*';                        Links=@(
        @{ Label='MS Learn : Stratégies de mot de passe'; Url='https://learn.microsoft.com/fr-fr/windows/security/threat-protection/security-policy-settings/password-policy' }
    )}
    @{ Cat='Comptes';        Pattern='Administrateurs locaux';    Links=@(
        @{ Label='MS Learn : Bonnes pratiques comptes admin locaux'; Url='https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory' }
    )}
    @{ Cat='Comptes';        Pattern='.*';                        Links=@(
        @{ Label='MS Learn : Sécurité des comptes locaux'; Url='https://learn.microsoft.com/fr-fr/windows-server/identity/securing-local-accounts-in-active-directory-domains' }
    )}
    @{ Cat='Defender';       Pattern='Exclusion';                 Links=@(
        @{ Label='MS Learn : Configurer des exclusions Defender'; Url='https://learn.microsoft.com/fr-fr/defender-endpoint/configure-exclusions-microsoft-defender-antivirus' }
    )}
    @{ Cat='Démarrage';      Pattern='.*';                        Links=@(
        @{ Label='Sysinternals Autoruns (analyse approfondie)'; Url='https://learn.microsoft.com/fr-fr/sysinternals/downloads/autoruns' }
    )}
    @{ Cat='Tâches planifiées'; Pattern='.*';                     Links=@(
        @{ Label='MS Learn : Planificateur de tâches — sécurité'; Url='https://learn.microsoft.com/fr-fr/windows/win32/taskschd/task-scheduler-start-page' }
        @{ Label='Sysinternals Autoruns — tâches planifiées';      Url='https://learn.microsoft.com/fr-fr/sysinternals/downloads/autoruns' }
    )}
    @{ Cat='UAC';            Pattern='.*';                        Links=@(
        @{ Label="MS Learn : Fonctionnement du contrôle de compte d'utilisateur"; Url='https://learn.microsoft.com/fr-fr/windows/security/application-security/application-control/user-account-control/how-it-works' }
    )}
    @{ Cat='Audit';          Pattern='.*';                        Links=@(
        @{ Label="MS Learn : Stratégie d'audit avancée";          Url='https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing' }
    )}
    @{ Cat='Mises à jour';   Pattern='.*';                        Links=@(
        @{ Label='MS Learn : Dépanner Windows Update';             Url='https://learn.microsoft.com/fr-fr/windows/deployment/update/windows-update-troubleshooting' }
    )}
    @{ Cat='Services';       Pattern='Services auto non-système'; Links=@(
        @{ Label='Sysinternals Autoruns — services';               Url='https://learn.microsoft.com/fr-fr/sysinternals/downloads/autoruns' }
        @{ Label='MS Learn : Sécuriser les services Windows';      Url='https://learn.microsoft.com/fr-fr/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10' }
    )}
    @{ Cat='Services';       Pattern='.*';                        Links=@(
        @{ Label='MS Learn : Gérer les services Windows';          Url='https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/sc-query' }
    )}
    @{ Cat='Système';        Pattern='Build|Uptime';              Links=@(
        @{ Label='MS Learn : Historique des builds Windows 11';    Url='https://learn.microsoft.com/fr-fr/windows/release-health/windows11-release-information' }
        @{ Label='MS Learn : Cycle de vie Windows';                Url='https://learn.microsoft.com/fr-fr/lifecycle/products/windows-11' }
    )}
    @{ Cat='Système';        Pattern='Signature du script';       Links=@(
        @{ Label='MS Learn : about_Signing (signature Authenticode)'; Url='https://learn.microsoft.com/fr-fr/powershell/module/microsoft.powershell.core/about/about_signing' }
    )}
    @{ Cat='Sauvegarde';     Pattern='Shadow Copy|VSS|Clichés';   Links=@(
        @{ Label='MS Learn : Vue d''ensemble du service VSS';         Url='https://learn.microsoft.com/fr-fr/windows-server/storage/file-server/volume-shadow-copy-service' }
        @{ Label='MS Learn : Créer un point de restauration système'; Url='https://support.microsoft.com/fr-fr/windows/créer-un-point-de-restauration-système-77e02e2a-3298-c869-9974-ef5658ea3be9' }
    )}
    @{ Cat='Certificats';    Pattern='expir';                      Links=@(
        @{ Label='MS Learn : Gérer les certificats avec PowerShell';  Url='https://learn.microsoft.com/fr-fr/powershell/module/pki/' }
    )}
    @{ Cat='Réseau';         Pattern='IPv6';                       Links=@(
        @{ Label='MS Learn : IPv6 et le pare-feu Windows Defender';   Url='https://learn.microsoft.com/fr-fr/windows/security/operating-system-security/network-security/windows-firewall/' }
    )}
    @{ Cat='Sécurité UEFI';  Pattern='Secure Boot';              Links=@(
        @{ Label='MS Learn : Vue d''ensemble Secure Boot';         Url='https://learn.microsoft.com/fr-fr/windows-hardware/design/device-experiences/oem-secure-boot' }
        @{ Label='MS Learn : Activer Secure Boot';                 Url='https://support.microsoft.com/fr-fr/windows/activer-le-démarrage-sécurisé-windows-66a8f21a-83d0-4a76-8b1e-e23f1c1a6e79' }
    )}
    @{ Cat='Sécurité UEFI';  Pattern='TPM';                      Links=@(
        @{ Label='MS Learn : Vue d''ensemble TPM';                 Url='https://learn.microsoft.com/fr-fr/windows/security/hardware-security/tpm/trusted-platform-module-overview' }
        @{ Label='MS Learn : Résoudre les problèmes TPM';          Url='https://learn.microsoft.com/fr-fr/windows/security/hardware-security/tpm/initialize-and-configure-ownership-of-the-tpm' }
    )}
    @{ Cat='Windows Hello';  Pattern='.*';                        Links=@(
        @{ Label='MS Learn : Vue d''ensemble Windows Hello Entreprise'; Url='https://learn.microsoft.com/fr-fr/windows/security/identity-protection/hello-for-business/' }
        @{ Label='MS Learn : Activer Windows Hello';               Url='https://support.microsoft.com/fr-fr/windows/configurer-windows-hello-dce28585-4661-583c-8c43-0f09d1db1f0f' }
    )}
)

function Get-HelpLinks {
    <#
    Retourne les liens d'aide contextuels pour un résultat (Catégorie +
    Contrôle) sous forme de HTML prêt à insérer, ou chaîne vide si aucune
    règle ne matche. Deux cas spéciaux gérés en dehors de la table
    générique car leur contenu dépend de la valeur exacte du résultat :
    - "Certificats" : recherche par EMPREINTE (crt.sh + Google), pas par
      nom — cohérent avec le choix fait en section 19 (empreinte = seule
      identité non falsifiable).
    - "Logiciels à surveiller" : recherche CVE (NVD) sur le nom + version
      exacts du logiciel détecté.
    #>
    param([string]$Categorie, [string]$Controle, [string]$Valeur, [string]$Detail)

    $links = [System.Collections.Generic.List[object]]::new()

    if ($Categorie -eq "Certificats" -and $Controle -like "Certificat racine :*") {
        $tpMatch = [regex]::Match($Detail, 'Empreinte \(SHA-1\) : ([0-9A-Fa-f]{40})')
        if ($tpMatch.Success) {
            $tp = $tpMatch.Groups[1].Value
            $links.Add(@{ Label='crt.sh (recherche par empreinte)'; Url="https://crt.sh/?q=$tp" })
        }
        $links.Add(@{ Label='MS Learn : Programme Trusted Root'; Url='https://learn.microsoft.com/fr-fr/security/trusted-root/program-requirements' })
        $cnSearch = [Uri]::EscapeDataString("$Valeur certificate authority")
        $links.Add(@{ Label='Recherche web sur cet émetteur'; Url="https://www.google.com/search?q=$cnSearch" })
    }
    elseif ($Categorie -eq "Logiciels" -and $Controle -like "Logiciel à surveiller :*") {
        $appName = ($Controle -replace '^Logiciel à surveiller : ', '').Trim()
        $cveQuery = [Uri]::EscapeDataString("$appName $Valeur")
        $links.Add(@{ Label='NVD : recherche de CVE'; Url="https://nvd.nist.gov/vuln/search/results?query=$cveQuery" })
    }
    else {
        foreach ($rule in $script:HelpLinksDb) {
            if ($rule.Cat -eq $Categorie -and $Controle -match $rule.Pattern) {
                foreach ($l in $rule.Links) { $links.Add($l) }
                break
            }
        }
    }

    if ($links.Count -eq 0) { return "" }

    $itemsHtml = ($links | ForEach-Object { "<a href='$(He $_.Url)' target='_blank' rel='noopener' class='help-link'>$(He $_.Label)</a>" }) -join ""
    return "<div class='help-links'>$itemsHtml</div>"
}

# Tableau global des résultats
$AuditResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Value,
        [string]$Status,   # OK / WARN / FAIL / INFO
        [string]$Detail = ""
    )
    $AuditResults.Add([PSCustomObject]@{
        Categorie = $Category
        Controle  = $Check
        Valeur    = $Value
        Statut    = $Status
        Detail    = $Detail
    })
    # NOTE v5.0.9 : $Message reste "$Category | $Check : $Value" pour le
    # fichier TXT (format inchangé) ; -Category/-Check/-Value en plus ne
    # servent qu'à l'alignement console dans Write-Log.
    Write-Log "$Category | $Check : $Value" -Level $Status -Category $Category -Check $Check -Value $Value
}

# ──────────────────────────────────────────────
#  MODE -SELFTEST
# ──────────────────────────────────────────────
# NOTE v4.3 : batterie d'assertions sur les fonctions internes du script.
# Exécution : .\Check-Security_Win11.ps1 -SelfTest
# Aucune connexion WMI/registre, aucun rapport généré, aucune modification.
# Même pattern que Analyze-WindowsLogs v6.6 (18 assertions, exit code 0/1).
if ($SelfTest) {
    $ST_Pass = 0; $ST_Fail = 0
    function Assert-SelfTest {
        param([string]$Name, [bool]$Condition, [string]$Detail = "")
        if ($Condition) {
            Write-Host "  [PASS] $Name" -ForegroundColor Green
            $script:ST_Pass++
        } else {
            Write-Host "  [FAIL] $Name$(if($Detail){" — $Detail"})" -ForegroundColor Red
            $script:ST_Fail++
        }
    }

    Write-Host ""
    Write-Host ("═" * 58) -ForegroundColor DarkCyan
    Write-Host "  Check-Security Win11 v$ScriptVersion — SelfTest" -ForegroundColor Cyan
    Write-Host ("═" * 58) -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  Fonctions utilitaires" -ForegroundColor DarkGray

    # He() — échappement HTML
    Assert-SelfTest "He() : & → &amp;"      ((He "&")      -eq "&amp;")
    Assert-SelfTest "He() : < → &lt;"       ((He "<")      -eq "&lt;")
    Assert-SelfTest "He() : > → &gt;"       ((He ">")      -eq "&gt;")
    Assert-SelfTest "He() : `" → &quot;"    ((He '"')      -eq "&quot;")
    Assert-SelfTest "He() : ' → &#39;"      ((He "'")      -eq "&#39;")
    Assert-SelfTest "He() : null → vide"    ((He $null)    -eq "")

    # Get-StatusBadge
    Assert-SelfTest "Get-StatusBadge OK"   ((Get-StatusBadge "OK")   -match "ok")
    Assert-SelfTest "Get-StatusBadge WARN" ((Get-StatusBadge "WARN") -match "warn")
    Assert-SelfTest "Get-StatusBadge FAIL" ((Get-StatusBadge "FAIL") -match "fail")
    Assert-SelfTest "Get-StatusBadge INFO" ((Get-StatusBadge "INFO") -match "info")

    # Add-Result — vérifie qu'un appel ajoute bien un élément avec les bons champs
    $script:AuditResults = [System.Collections.Generic.List[object]]::new()
    Add-Result "TestCat" "TestCtrl" "TestVal" "OK" "TestDetail"
    Assert-SelfTest "Add-Result : élément ajouté"          ($AuditResults.Count -eq 1)
    Assert-SelfTest "Add-Result : Categorie correcte"      ($AuditResults[0].Categorie -eq "TestCat")
    Assert-SelfTest "Add-Result : Statut correct"          ($AuditResults[0].Statut   -eq "OK")
    Assert-SelfTest "Add-Result : Detail correct"          ($AuditResults[0].Detail   -eq "TestDetail")
    $script:AuditResults = [System.Collections.Generic.List[object]]::new()  # reset

    Write-Host ""
    Write-Host "  Moteur de scoring" -ForegroundColor DarkGray

    # Scoring pondéré : 1 FAIL + 1 WARN + 1 OK dans catégorie poids 2.0
    # taux = (0.0 + 0.5 + 1.0) / 3 = 0.5 → score = round(100 × (2.0×0.5)/(2.0)) = 50
    $ST_TestResults = @(
        [PSCustomObject]@{ Categorie="X"; Statut="FAIL" },
        [PSCustomObject]@{ Categorie="X"; Statut="WARN" },
        [PSCustomObject]@{ Categorie="X"; Statut="OK"   }
    )
    $ST_Weights = @{ "X" = 2.0 }
    $ST_CatStats = @{ "X" = @{ WeightedSum = 0.0; Count = 0 } }
    foreach ($r in $ST_TestResults) {
        $v = switch($r.Statut) { "OK"{1.0} "INFO"{1.0} "WARN"{0.5} "FAIL"{0.0} default{1.0} }
        $ST_CatStats["X"].WeightedSum += $v; $ST_CatStats["X"].Count++
    }
    $ST_num = $ST_Weights["X"] * ($ST_CatStats["X"].WeightedSum / $ST_CatStats["X"].Count)
    $ST_den = $ST_Weights["X"]
    $ST_Score = [int][math]::Round(100 * $ST_num / $ST_den)
    Assert-SelfTest "Scoring pondéré (1 FAIL+1 WARN+1 OK, poids 2.0 → 50)" ($ST_Score -eq 50) "Obtenu : $ST_Score"

    Write-Host ""
    Write-Host "  Configuration" -ForegroundColor DarkGray

    Assert-SelfTest "CategoryWeights : BitLocker présent"     ($CategoryWeights.ContainsKey("BitLocker"))
    Assert-SelfTest "CategoryWeights : TLS/SCHANNEL présent"  ($CategoryWeights.ContainsKey("TLS/SCHANNEL"))
    Assert-SelfTest "CategoryWeights : Démarrage présent"     ($CategoryWeights.ContainsKey("Démarrage"))
    Assert-SelfTest "CategoryWeights : Pare-feu présent"      ($CategoryWeights.ContainsKey("Pare-feu"))
    Assert-SelfTest "CategoryWeights : VBS présent"           ($CategoryWeights.ContainsKey("VBS"))
    Assert-SelfTest "ScoreRegressionThreshold > 0"            ($ScoreRegressionThreshold -gt 0)
    Assert-SelfTest "TrustedRootThumbprintAllowlist non vide" ($TrustedRootThumbprintAllowlist.Count -gt 0)
    Assert-SelfTest "TrustedTaskNames non vide"               ($TrustedTaskNames.Count -gt 0)

    Write-Host ""
    Write-Host "  Nouvelles fonctionnalités v4.4" -ForegroundColor DarkGray

    # BitLocker : vérifier que la logique C: FAIL / autres WARN est correcte
    # On simule deux volumes fictifs et on vérifie le switch
    $ST_SystemDrive = $env:SystemDrive
    $ST_VolSystem = [PSCustomObject]@{ MountPoint = $ST_SystemDrive; ProtectionStatus = "Off"; EncryptionPercentage = 0 }
    $ST_VolData   = [PSCustomObject]@{ MountPoint = "E:";            ProtectionStatus = "Off"; EncryptionPercentage = 0 }
    $ST_IsSystem  = ("$($ST_VolSystem.MountPoint)".TrimEnd('\') -eq $ST_SystemDrive)
    $ST_IsData    = ("$($ST_VolData.MountPoint)".TrimEnd('\')   -eq $ST_SystemDrive)
    $ST_StSystem  = if ($ST_IsSystem) { "FAIL" } else { "WARN" }
    $ST_StData    = if ($ST_IsData)   { "FAIL" } else { "WARN" }
    Assert-SelfTest "BitLocker : volume système → FAIL"       ($ST_StSystem -eq "FAIL") "Obtenu : $ST_StSystem"
    Assert-SelfTest "BitLocker : volume non-système → WARN"   ($ST_StData   -eq "WARN") "Obtenu : $ST_StData"

    # SmartScreen : vérifier que la clé registre est lisible (pas de test de valeur,
    # juste que Get-ItemProperty ne lève pas d'exception inattendue)
    $ST_SSKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $ST_SSReadable = $false
    try {
        $null = Get-ItemProperty -Path $ST_SSKey -ErrorAction Stop
        $ST_SSReadable = $true
    } catch {}
    Assert-SelfTest "SmartScreen : clé registre Explorer lisible" $ST_SSReadable

    # Exploit Protection : vérifier que Get-ProcessMitigation est disponible
    $ST_MitAvailable = $null -ne (Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue)
    Assert-SelfTest "Exploit Protection : Get-ProcessMitigation disponible" $ST_MitAvailable

    # Section 21 : vérifier que la clé CI\Config est accessible en lecture
    $ST_CIKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
    $ST_CIReadable = Test-Path -LiteralPath $ST_CIKey -ErrorAction SilentlyContinue
    # Test-Path retourne $false si absent mais ne plante pas — c'est le comportement attendu
    Assert-SelfTest "Section 21 : clé CI\Config accessible (présente ou absente sans erreur)" ($null -ne $ST_CIReadable)

    # DeltaMap : vérifier que la construction fonctionne sur un jeu vide
    $ST_Deltas = @()
    $ST_DeltaMap = @{}
    foreach ($d in $ST_Deltas) { $ST_DeltaMap["$($d.Categorie)|$($d.Controle)"] = $d.Type }
    Assert-SelfTest "DeltaMap : construction sur liste vide → hashtable vide" ($ST_DeltaMap.Count -eq 0)

    # DeltaMap : avec un delta fictif
    $ST_Deltas2 = @([PSCustomObject]@{ Categorie="Test"; Controle="Ctrl"; Type="Résolu" })
    $ST_DeltaMap2 = @{}
    foreach ($d in $ST_Deltas2) { $ST_DeltaMap2["$($d.Categorie)|$($d.Controle)"] = $d.Type }
    Assert-SelfTest "DeltaMap : clé Categorie|Controle correcte" ($ST_DeltaMap2.ContainsKey("Test|Ctrl"))
    Assert-SelfTest "DeltaMap : valeur Type correcte"            ($ST_DeltaMap2["Test|Ctrl"] -eq "Résolu")

    Write-Host ""
    Write-Host "  Nouvelles fonctionnalités v5.0" -ForegroundColor DarkGray

    # -Category : si vide, ShouldRunSection doit retourner $true
    $ST_CatEmpty = ShouldRunSection "7_BitLocker"
    Assert-SelfTest "ShouldRunSection : -Category vide → toujours true" $ST_CatEmpty "Obtenu : $ST_CatEmpty"

    # -Category : filtre fonctionnel
    $script:Category = @("BitLocker")
    $ST_CatMatch    = ShouldRunSection "7_BitLocker"
    $ST_CatNoMatch  = ShouldRunSection "20_TLS"
    Assert-SelfTest "ShouldRunSection : 'BitLocker' → 7_BitLocker OK" $ST_CatMatch
    Assert-SelfTest "ShouldRunSection : 'BitLocker' → 20_TLS exclu" (-not $ST_CatNoMatch)
    $script:Category = @()  # reset

    # VSS : vérifier que le service est lisible sans exception
    $ST_VSSReadable = $false
    try {
        $null = Get-Service -Name VSS -ErrorAction Stop
        $ST_VSSReadable = $true
    } catch {}
    Assert-SelfTest "VSS : service Get-Service VSS disponible" $ST_VSSReadable

    # Certificats : magasin LocalMachine\My accessible
    $ST_MyStoreReadable = $false
    try {
        $null = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop
        $ST_MyStoreReadable = $true
    } catch {}
    Assert-SelfTest "Certificats : Cert:\LocalMachine\My accessible" $ST_MyStoreReadable

    # CategoryWeights : Sauvegarde présent (nouveau en v5)
    Assert-SelfTest "CategoryWeights : Sauvegarde présent" ($CategoryWeights.ContainsKey("Sauvegarde"))

    # RID-500 : vérifier que Get-LocalUser est disponible
    $ST_LocalUserAvail = $null -ne (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)
    Assert-SelfTest "Comptes : Get-LocalUser disponible pour RID-500" $ST_LocalUserAvail

    Write-Host ""
    Write-Host ("═" * 58) -ForegroundColor DarkCyan
    $allOK = $ST_Fail -eq 0
    $color  = if ($allOK) { "Green" } else { "Red" }
    $emoji  = if ($allOK) { "✓" } else { "✗" }
    Write-Host "  $emoji  SelfTest : $ST_Pass PASS · $ST_Fail FAIL" -ForegroundColor $color
    Write-Host ("═" * 58) -ForegroundColor DarkCyan
    Write-Host ""
    exit $(if ($allOK) { 0 } else { 1 })
}

# ──────────────────────────────────────────────
#  1. INFORMATIONS SYSTÈME
# ──────────────────────────────────────────────
Write-Log "=== 1. INFORMATIONS SYSTÈME ===" -Level SECTION

$OS   = Get-CimInstance Win32_OperatingSystem
$CS   = Get-CimInstance Win32_ComputerSystem
$BIOS = Get-CimInstance Win32_BIOS
$CPU  = Get-CimInstance Win32_Processor | Select-Object -First 1

Add-Result "Système" "Nom de la machine"      $env:COMPUTERNAME          "INFO"
Add-Result "Système" "Système d'exploitation" "$($OS.Caption) $($OS.BuildNumber)" "INFO"
Add-Result "Système" "Version OS"             $OS.Version                "INFO"
Add-Result "Système" "Architecture"           $OS.OSArchitecture         "INFO"
Add-Result "Système" "Domaine / Groupe"       "$($CS.Domain)"            "INFO"
Add-Result "Système" "Dernier démarrage"      "$($OS.LastBootUpTime)"    "INFO"
Add-Result "Système" "BIOS Version"           "$($BIOS.SMBIOSBIOSVersion)" "INFO"
Add-Result "Système" "Processeur"             $CPU.Name                  "INFO"

# Vérifier si Windows 11
$Build = [int]$OS.BuildNumber
if ($Build -ge 22000) {
    Add-Result "Système" "Build Windows 11" "Build $Build (Windows 11)" "OK"
} else {
    Add-Result "Système" "Build Windows 11" "Build $Build (Pas Windows 11 !)" "FAIL" "Ce script est optimisé pour Windows 11 (Build ≥ 22000)"
}

# Uptime
$Uptime = (Get-Date) - $OS.LastBootUpTime
if ($Uptime.TotalDays -gt 30) {
    Add-Result "Système" "Uptime machine" "$([math]::Round($Uptime.TotalDays,1)) jours" "WARN" "Machine non redémarrée depuis plus de 30 jours — patchs en attente ?"
} else {
    Add-Result "Système" "Uptime machine" "$([math]::Round($Uptime.TotalDays,1)) jours" "OK"
}

# NOTE v3.0 : signature Authenticode du script lui-même, cohérence avec
# l'usage de Sign-MyScripts.ps1 sur le reste de la suite. $PSCommandPath est
# vide si le script est collé/exécuté en ligne (pas de fichier sur disque) —
# on traite ce cas en INFO plutôt qu'en erreur, ce n'est pas une anomalie.
if ($PSCommandPath) {
    try {
        $ScriptSig = Get-AuthenticodeSignature -FilePath $PSCommandPath -ErrorAction Stop
        switch ($ScriptSig.Status) {
            "Valid" {
                Add-Result "Système" "Signature du script" "Valide" "OK" "Signé par : $($ScriptSig.SignerCertificate.Subject)"
            }
            "NotSigned" {
                Add-Result "Système" "Signature du script" "Non signé" "INFO" "Ce script n'est pas signé — pas un risque en soi sur un poste personnel, mais incohérent avec ta chaîne de signature habituelle (Sign-MyScripts.ps1)"
            }
            default {
                Add-Result "Système" "Signature du script" "$($ScriptSig.Status)" "WARN" "Statut de signature inattendu — vérifie que le script n'a pas été modifié depuis sa signature"
            }
        }
    } catch {
        Add-Result "Système" "Signature du script" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
    }
} else {
    Add-Result "Système" "Signature du script" "Non vérifiable" "INFO" "Script exécuté sans chemin de fichier sur disque (collé directement en console, par exemple)"
}

# ──────────────────────────────────────────────
#  2. WINDOWS UPDATE & PATCHES
# ──────────────────────────────────────────────
Write-Log "=== 2. WINDOWS UPDATE & PATCHES ===" -Level SECTION

try {
    $HotFixes = Get-HotFix | Sort-Object InstalledOn -Descending
    $LastPatch = $HotFixes | Select-Object -First 1
    $DaysSincePatch = ((Get-Date) - [datetime]$LastPatch.InstalledOn).TotalDays

    Add-Result "Mises à jour" "Nombre de patches installés" $HotFixes.Count "INFO"
    Add-Result "Mises à jour" "Dernier patch installé" "$($LastPatch.HotFixID) le $($LastPatch.InstalledOn)" $(
        if ($DaysSincePatch -gt 60) { "FAIL" } elseif ($DaysSincePatch -gt 30) { "WARN" } else { "OK" }
    ) "$(if($DaysSincePatch -gt 60){'Aucun patch depuis plus de 60 jours'}elseif($DaysSincePatch -gt 30){'Aucun patch depuis plus de 30 jours'}else{'Patch récent'})"
} catch {
    Add-Result "Mises à jour" "Lecture des patches" "Erreur : $_" "WARN"
}

# Windows Update Service
$WUSvc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if ($WUSvc) {
    $status = if ($WUSvc.StartType -eq "Disabled") { "FAIL" } else { "OK" }
    Add-Result "Mises à jour" "Service Windows Update" "$($WUSvc.Status) / Démarrage : $($WUSvc.StartType)" $status $(
        if ($WUSvc.StartType -eq "Disabled") { "Le service Windows Update est désactivé !" }
    )
}

# ──────────────────────────────────────────────
#  3. PARE-FEU WINDOWS
# ──────────────────────────────────────────────
Write-Log "=== 3. PARE-FEU WINDOWS ===" -Level SECTION

$Profiles = @("Domain","Private","Public")
foreach ($profile in $Profiles) {
    try {
        $fw = Get-NetFirewallProfile -Profile $profile -ErrorAction Stop
        $st = if ($fw.Enabled) { "OK" } else { "FAIL" }
        Add-Result "Pare-feu" "Profil $profile" $(if ($fw.Enabled) {"Activé"} else {"DÉSACTIVÉ"}) $st $(
            if (-not $fw.Enabled) { "Le pare-feu profil $profile est désactivé — risque élevé !" }
        )
        # Politique par défaut
        Add-Result "Pare-feu" "Politique entrante $profile" $fw.DefaultInboundAction "INFO"
        Add-Result "Pare-feu" "Politique sortante $profile" $fw.DefaultOutboundAction "INFO"
    } catch {
        Add-Result "Pare-feu" "Profil $profile" "Non disponible" "WARN"
    }
}

# Règles entrantes permissives (Any)
# NOTE v1.1 : compter toute règle Allow/Enabled sur le profil Public surestime
# le risque — la plupart de ces règles sont scopées à un programme ou un port
# précis (comportement par défaut normal de Windows), pas réellement ouvertes
# à n'importe quelle source. On distingue maintenant le total (informatif) du
# sous-ensemble réellement ouvert à toute adresse distante (le vrai risque).
$PublicAllowRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.Profile -match "Public" }

Add-Result "Pare-feu" "Règles entrantes actives (Public)" $PublicAllowRules.Count "INFO" "Inclut les règles scopées par programme/port — normal sur une installation Windows standard"

$TrulyOpenRules = [System.Collections.Generic.List[object]]::new()
foreach ($rule in $PublicAllowRules) {
    $addrFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
    if ($addrFilter -and ($addrFilter.RemoteAddress -contains "Any")) {
        $TrulyOpenRules.Add($rule)
    }
}

Add-Result "Pare-feu" "Règles entrantes ouvertes à toute IP (Public)" $TrulyOpenRules.Count "INFO" "Voir le détail par éditeur ci-dessous — Microsoft (INFO), tiers signés (WARN), non signés (WARN)"

# NOTE v4.4 : classification des règles ouvertes par éditeur/signature de
# l'exécutable associé. Un comptage brut (31 règles) ne dit rien du risque —
# une règle Microsoft native (Wi-Fi Direct, mDNS…) n'a pas le même poids
# qu'un exécutable non signé dans AppData. On classe en trois niveaux :
# - Microsoft signé  → INFO  (règle native Windows, légitime)
# - Tiers signé      → WARN  (règle d'application connue)
# - Non signé/inconnu→ WARN fort (à vérifier manuellement)
$FwMicrosoft = [System.Collections.Generic.List[string]]::new()
$FwThirdParty= [System.Collections.Generic.List[string]]::new()
$FwUnsigned  = [System.Collections.Generic.List[string]]::new()

foreach ($rule in $TrulyOpenRules) {
    $appFilter = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    $exePath   = if ($appFilter) { $appFilter.Program } else { $null }

    if (-not $exePath -or $exePath -eq "Any" -or $exePath -eq "") {
        # Règle sans exécutable associé (port only)
        # Microsoft Store, UWP apps, Windows Features → traiter comme Microsoft
        $ruleName = $rule.DisplayName
        if ($ruleName -match "Microsoft Store|Windows|Visionneuse|Pack d'expérience|Plateforme") {
            $FwMicrosoft.Add($ruleName)
        } else {
            $FwUnsigned.Add("$ruleName [port seul, pas d'exe]")
        }
        continue
    }

    # NOTE v4.5 : expander les variables d'environnement avant Get-AuthenticodeSignature.
    # Les chemins comme %SystemRoot%\system32\svchost.exe ne sont pas résolus
    # automatiquement par Get-AuthenticodeSignature → échec silencieux → faux
    # positif "non signé". [Environment]::ExpandEnvironmentVariables() résout le chemin.
    $exeResolved = [Environment]::ExpandEnvironmentVariables($exePath)

    # Exécutables Windows natifs dans System32 — Microsoft par définition,
    # pas besoin de vérifier la signature (et "System" = driver noyau).
    if ($exeResolved -match "(?i)\\windows\\system32\\" -or $exePath -eq "System") {
        $FwMicrosoft.Add("$($rule.DisplayName)")
        continue
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $exeResolved -ErrorAction Stop
        if ($sig.Status -eq "Valid") {
            $publisher = $sig.SignerCertificate.Subject
            if ($publisher -match "Microsoft") {
                $FwMicrosoft.Add("$($rule.DisplayName)")
            } else {
                $FwThirdParty.Add("$($rule.DisplayName) [$publisher]")
            }
        } else {
            $FwUnsigned.Add("$($rule.DisplayName) [$exeResolved — $($sig.Status)]")
        }
    } catch {
        $FwUnsigned.Add("$($rule.DisplayName) [$exeResolved — non vérifié]")
    }
}

if ($FwMicrosoft.Count -gt 0) {
    Add-Result "Pare-feu" "Règles ouvertes — éditeur Microsoft" $FwMicrosoft.Count "INFO" "Règles natives Windows (légitimes) : $($FwMicrosoft -join ' | ')"
}
if ($FwThirdParty.Count -gt 0) {
    Add-Result "Pare-feu" "Règles ouvertes — éditeur tiers signé" $FwThirdParty.Count "WARN" "Règles d'applications tierces signées — à vérifier si les logiciels sont attendus : $($FwThirdParty -join ' | ')"
}
if ($FwUnsigned.Count -gt 0) {
    Add-Result "Pare-feu" "Règles ouvertes — exécutable non signé/inconnu" $FwUnsigned.Count "WARN" "Règles sans signature valide ou sans exe associé — à examiner manuellement : $($FwUnsigned -join ' | ')"
}

# NOTE v3.0 : un comptage brut de règles "ouvertes à toute IP" ne dit rien du
# risque réel — une règle ouverte sur un port applicatif obscur n'a pas le
# même poids qu'une règle ouverte sur RDP/SMB/WinRM. On reclasse maintenant
# chaque règle réellement ouverte selon le port qu'elle expose, avec une
# liste de ports notoirement sensibles signalés en FAIL.
$DangerousPorts = @{
    3389 = "RDP"; 445 = "SMB"; 139 = "NetBIOS"; 135 = "RPC"
    5985 = "WinRM (HTTP)"; 5986 = "WinRM (HTTPS)"; 23 = "Telnet"
    21 = "FTP"; 1433 = "SQL Server"; 3306 = "MySQL"; 5900 = "VNC"
}
foreach ($rule in $TrulyOpenRules) {
    $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    if (-not $portFilter) { continue }
    foreach ($portEntry in @($portFilter.LocalPort)) {
        $portNum = 0
        if ([int]::TryParse("$portEntry", [ref]$portNum) -and $DangerousPorts.ContainsKey($portNum)) {
            Add-Result "Pare-feu" "Port sensible exposé à toute IP : $($DangerousPorts[$portNum]) ($portNum)" $rule.DisplayName "FAIL" "Cette règle autorise le port $portNum ($($DangerousPorts[$portNum])) depuis n'importe quelle adresse distante sur le profil Public — à restreindre à une plage d'IP de confiance ou désactiver si non utilisé"
        }
    }
}

# ──────────────────────────────────────────────
#  4. ANTIVIRUS / WINDOWS DEFENDER
# ──────────────────────────────────────────────
Write-Log "=== 4. ANTIVIRUS / WINDOWS DEFENDER ===" -Level SECTION

try {
    $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop

    $avEnabled = $DefenderStatus.AntivirusEnabled
    Add-Result "Antivirus" "Antivirus activé"          $(if($avEnabled){"Oui"}else{"NON"})          $(if($avEnabled){"OK"}else{"FAIL"})
    Add-Result "Antivirus" "Protection temps réel"     $(if($DefenderStatus.RealTimeProtectionEnabled){"Activée"}else{"DÉSACTIVÉE"})  $(if($DefenderStatus.RealTimeProtectionEnabled){"OK"}else{"FAIL"})
    Add-Result "Antivirus" "Protection réseau"         $(if($DefenderStatus.IoavProtectionEnabled){"Activée"}else{"Désactivée"})      $(if($DefenderStatus.IoavProtectionEnabled){"OK"}else{"WARN"})
    Add-Result "Antivirus" "Protection comportementale"$(if($DefenderStatus.BehaviorMonitorEnabled){"Activée"}else{"Désactivée"})     $(if($DefenderStatus.BehaviorMonitorEnabled){"OK"}else{"WARN"})

    $SigAge = ((Get-Date) - $DefenderStatus.AntivirusSignatureLastUpdated).TotalDays
    Add-Result "Antivirus" "Signatures AV (âge)"      "$([math]::Round($SigAge,1)) jours" $(
        if ($SigAge -gt 7) { "FAIL" } elseif ($SigAge -gt 3) { "WARN" } else { "OK" }
    ) $(if($SigAge -gt 7){"Signatures obsolètes !"}elseif($SigAge -gt 3){"Signatures anciennes"})

    Add-Result "Antivirus" "Version signatures"        $DefenderStatus.AntivirusSignatureVersion "INFO"

    # NOTE v5.0 : signatures Antispyware et NIS — deux composantes indépendantes
    # de l'AV qui peuvent dériver séparément si la mise à jour automatique est
    # partiellement défaillante (ex: l'AV se met à jour mais pas le NIS).
    try {
        $SpyAge = ((Get-Date) - $DefenderStatus.AntispywareSignatureLastUpdated).TotalDays
        Add-Result "Antivirus" "Signatures Anti-Spyware (âge)" "$([math]::Round($SpyAge,1)) jours" $(
            if ($SpyAge -gt 7) { "FAIL" } elseif ($SpyAge -gt 3) { "WARN" } else { "OK" }
        ) $(if($SpyAge -gt 7){"Signatures anti-spyware obsolètes"}elseif($SpyAge -gt 3){"Signatures anti-spyware anciennes"})
    } catch {}

    try {
        $NISAge = ((Get-Date) - $DefenderStatus.NISSignatureLastUpdated).TotalDays
        Add-Result "Antivirus" "Signatures NIS (Network Inspection, âge)" "$([math]::Round($NISAge,1)) jours" $(
            if ($NISAge -gt 7) { "FAIL" } elseif ($NISAge -gt 3) { "WARN" } else { "OK" }
        ) $(if($NISAge -gt 7){"Signatures NIS obsolètes — module d'inspection réseau de Defender non à jour"}elseif($NISAge -gt 3){"Signatures NIS anciennes"})
    } catch {}

    # NOTE v5.0.7 : refonte du check scan Defender.
    # Ancien modèle (v1.1→v5.0.6) : seul le full scan était surveillé, seuils
    # 7j WARN / 30j FAIL. Problème : Defender sur Win11 privilégie les quick
    # scans quotidiens automatiques et ne lance pas de full scan spontanément —
    # un full scan absent depuis 11 jours est normal et générait un WARN
    # injustifié à chaque audit (cas NEPH-DESKTOP observé en run v5.0.x).
    #
    # Nouveau modèle : deux contrôles distincts avec seuils adaptés.
    # 1. QUICK SCAN (indicateur principal) — doit tourner au moins tous les 3j.
    #    >3j WARN, >7j FAIL. Un quick scan absent = Defender perturbé ou arrêté.
    # 2. FULL SCAN (indicateur secondaire) — seuils larges, fréquence optionnelle.
    #    >30j WARN, >90j FAIL, jamais lancé = INFO (pas une anomalie en soi).

    # 1. Quick scan
    if (-not $DefenderStatus.QuickScanEndTime -or
        $DefenderStatus.QuickScanEndTime -lt [datetime]"2000-01-01") {
        Add-Result "Antivirus" "Dernier quick scan" "Aucun quick scan enregistré" "WARN" "Aucun quick scan récent détecté — vérifier que Defender fonctionne correctement : 'Start-MpScan -ScanType QuickScan'"
    } else {
        $DaysSinceQuick = [math]::Round(((Get-Date) - $DefenderStatus.QuickScanEndTime).TotalDays, 1)
        $quickStatus = if ($DaysSinceQuick -gt 7) { "FAIL" } elseif ($DaysSinceQuick -gt 3) { "WARN" } else { "OK" }
        $quickDetail = switch ($quickStatus) {
            "FAIL" { "Dernier quick scan il y a $DaysSinceQuick jours — Defender ne scanne plus automatiquement, vérifier l'état du service : 'Get-MpComputerStatus'" }
            "WARN" { "Dernier quick scan il y a $DaysSinceQuick jours — Defender devrait lancer un quick scan automatique tous les 1-2 jours" }
            default { "Quick scan récent ($DaysSinceQuick jour(s))" }
        }
        Add-Result "Antivirus" "Dernier quick scan" "$($DefenderStatus.QuickScanEndTime.ToString('dd/MM/yyyy HH:mm'))" $quickStatus $quickDetail
    }

    # 2. Full scan (seuils larges — fréquence optionnelle sur poste personnel)
    if (-not $DefenderStatus.FullScanEndTime -or
        $DefenderStatus.FullScanEndTime -lt [datetime]"2000-01-01") {
        Add-Result "Antivirus" "Dernier scan complet" "Aucun scan complet enregistré" "INFO" "Aucun full scan dans l'historique — normal si Defender gère les scans automatiquement (quick scans quotidiens). Lancer occasionnellement : 'Start-MpScan -ScanType FullScan'"
    } else {
        $DaysSinceFullScan = [math]::Round(((Get-Date) - $DefenderStatus.FullScanEndTime).TotalDays, 1)
        $scanStatus = if ($DaysSinceFullScan -gt 90) { "FAIL" } elseif ($DaysSinceFullScan -gt 30) { "WARN" } else { "OK" }
        $scanDetail = switch ($scanStatus) {
            "FAIL" { "Dernier scan complet il y a $DaysSinceFullScan jours — très ancien, envisager un full scan : 'Start-MpScan -ScanType FullScan'" }
            "WARN" { "Dernier scan complet il y a $DaysSinceFullScan jours — un full scan mensuel est recommandé" }
            default { "Scan complet récent ($DaysSinceFullScan jour(s))" }
        }
        Add-Result "Antivirus" "Dernier scan complet" "$($DefenderStatus.FullScanEndTime.ToString('dd/MM/yyyy HH:mm'))" $scanStatus $scanDetail
    }

    # NOTE v1.1 : AMSIEnabled n'est plus exposé par Get-MpComputerStatus sur
    # certaines builds récentes — une valeur absente ($null) ne veut pas dire
    # "désactivé". On distingue maintenant "non exposé" de "réellement désactivé".
    if ($null -eq $DefenderStatus.PSObject.Properties['AMSIEnabled'] -or $null -eq $DefenderStatus.AMSIEnabled) {
        Add-Result "Antivirus" "AMSI activé" "Non exposé par cette build" "INFO" "Get-MpComputerStatus ne renvoie plus cette propriété sur certaines versions récentes ; AMSI reste actif par défaut sauf désactivation explicite via GPO"
    } else {
        Add-Result "Antivirus" "AMSI activé" $(if($DefenderStatus.AMSIEnabled){"Oui"}else{"Non"}) $(if($DefenderStatus.AMSIEnabled){"OK"}else{"WARN"})
    }

} catch {
    Add-Result "Antivirus" "Windows Defender" "Impossible de lire le statut : $_" "WARN"
}

# Vérifier si un autre AV est installé
try {
    $AVProducts = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    foreach ($av in $AVProducts) {
        Add-Result "Antivirus" "Produit AV détecté" $av.displayName "INFO" "État : $($av.productState)"
    }
} catch {}

# NOTE v3.0 : règles ASR (Attack Surface Reduction) — bloquent des
# techniques d'attaque génériques (macros Office lançant des process enfants,
# scripts obfusqués, exécutables non signés depuis un email, etc.) en amont
# de la détection par signature. Ids/Actions sont deux tableaux parallèles
# (même index = même règle). Action 1 = Block, 2 = Audit, 0/absent = Off.
try {
    $AsrPrefs   = Get-MpPreference -ErrorAction Stop
    $AsrIds     = @($AsrPrefs.AttackSurfaceReductionRules_Ids)
    $AsrActions = @($AsrPrefs.AttackSurfaceReductionRules_Actions)
    $AsrBlocking = 0
    $AsrAuditing = 0
    for ($i = 0; $i -lt $AsrIds.Count; $i++) {
        if ($i -lt $AsrActions.Count) {
            if ([int]$AsrActions[$i] -eq 1) { $AsrBlocking++ }
            elseif ([int]$AsrActions[$i] -eq 2) { $AsrAuditing++ }
        }
    }
    if ($AsrIds.Count -eq 0) {
        Add-Result "Antivirus" "Règles ASR (Attack Surface Reduction)" "Aucune règle configurée" "WARN" "Les règles ASR bloquent des techniques d'attaque génériques (macros Office, scripts obfusqués, etc.) indépendamment des signatures — aucune n'est active sur ce poste. Voir 'Add-MpPreference -AttackSurfaceReductionRules_Ids ... -AttackSurfaceReductionRules_Actions Enabled'"
    } else {
        Add-Result "Antivirus" "Règles ASR (Attack Surface Reduction)" "$($AsrIds.Count) règle(s) configurée(s)" $(
            if ($AsrBlocking -eq 0) { "WARN" } else { "OK" }
        ) "$AsrBlocking en blocage, $AsrAuditing en audit seul, $($AsrIds.Count - $AsrBlocking - $AsrAuditing) inactive(s)"
    }
} catch {
    Add-Result "Antivirus" "Règles ASR (Attack Surface Reduction)" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
}

# NOTE v4.6 : historique des détections Defender sur les 30 derniers jours.
# Get-MpThreatDetection retourne toutes les menaces détectées et traitées
# (quarantaine, suppression, blocage). 0 détection = machine propre depuis
# 30 jours. Des détections récentes ne signalent pas forcément un compromis
# actif — Defender peut avoir bloqué un téléchargement ou une PUA sans
# intervention de l'utilisateur — mais elles méritent d'être visibles.
try {
    $ThreatHistory = Get-MpThreatDetection -ErrorAction Stop
    $Since30Days   = if ($null -eq $ThreatHistory) { @() } else {
        @($ThreatHistory | Where-Object {
            $_.InitialDetectionTime -ge (Get-Date).AddDays(-30)
        })
    }

    if ($Since30Days.Count -eq 0) {
        Add-Result "Defender" "Historique détections (30 jours)" "0 détection" "OK" "Aucune menace détectée par Windows Defender sur les 30 derniers jours"
    } else {
        # Construire une map ThreatID → ThreatName en une seule requête
        $ThreatMap = @{}
        try {
            Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object {
                $ThreatMap[[string]$_.ThreatID] = $_.ThreatName
            }
        } catch {}

        $threatDetails = $Since30Days | Select-Object -First 10 | ForEach-Object {
            $name   = if ($ThreatMap.ContainsKey([string]$_.ThreatID)) { $ThreatMap[[string]$_.ThreatID] } else { "ID $($_.ThreatID)" }
            $status = if ($_.ActionSuccess) { "Traité" } else { "⚠ Non traité" }
            "$name — $status le $(Get-Date $_.InitialDetectionTime -Format 'dd/MM HH:mm')"
        }
        $moreNote   = if ($Since30Days.Count -gt 10) { " (+ $($Since30Days.Count - 10) autre(s))" } else { "" }
        $hasUntreated = $Since30Days | Where-Object { -not $_.ActionSuccess }
        $detStatus  = if ($hasUntreated) { "WARN" } else { "INFO" }
        Add-Result "Defender" "Historique détections (30 jours)" "$($Since30Days.Count) détection(s)$moreNote" $detStatus "Menaces$(if($hasUntreated){' — ⚠ AU MOINS UNE NON TRAITÉE'}) : $($threatDetails -join ' | ')"
    }
} catch {
    Add-Result "Defender" "Historique détections (30 jours)" "Lecture impossible" "INFO" "Get-MpThreatDetection indisponible : $($_.Exception.Message)"
}

# ──────────────────────────────────────────────
#  5. COMPTES UTILISATEURS & POLITIQUES
# ──────────────────────────────────────────────
Write-Log "=== 5. COMPTES UTILISATEURS ===" -Level SECTION

# NOTE v2.0 : détection de Windows Hello (PIN/biométrie) au niveau machine,
# calculée ici pour pouvoir contextualiser le flag SAM "mot de passe non
# requis" ci-dessous au lieu de se contenter de suggérer une vérification
# manuelle. Le détail (section dédiée) est affiché plus loin, section 17.
# NOTE v2.0 : détection de Windows Hello (PIN/biométrie) au niveau machine,
# calculée ici pour pouvoir contextualiser le flag SAM "mot de passe non
# requis" ci-dessous au lieu de se contenter de suggérer une vérification
# manuelle. Le détail (section dédiée) est affiché plus loin, section 17.
#
# NOTE v2.1 : le chemin "ServiceProfiles\LocalService\...\Ngc" est protégé par
# des ACL système — même en tant qu'administrateur (pas SYSTEM), la lecture
# de ce dossier échoue généralement par accès refusé. L'ancienne version
# avalait cette erreur silencieusement et concluait à tort "Non détecté".
# On ajoute le conteneur NGC propre à l'utilisateur courant (accessible sans
# élévation particulière, car on est ce même utilisateur derrière le token
# admin), et on distingue désormais un vrai "non configuré" d'un "accès
# refusé, donc indéterminable" pour ne pas affirmer ce qu'on n'a pas pu vérifier.
$HelloConfigured  = $false
$HelloIndeterminate = $false

$NgcPathsToCheck = @(
    "$env:WINDIR\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc",
    "$env:LOCALAPPDATA\Microsoft\Ngc"
)
foreach ($ngcPath in $NgcPathsToCheck) {
    try {
        if (Test-Path -LiteralPath $ngcPath -ErrorAction Stop) {
            $NgcItems = Get-ChildItem -LiteralPath $ngcPath -Force -ErrorAction Stop
            if ((($NgcItems | Measure-Object).Count) -gt 0) { $HelloConfigured = $true }
        }
    } catch [System.UnauthorizedAccessException] {
        $HelloIndeterminate = $true
    } catch {
        # Chemin absent ou autre erreur bénigne : pas de signal, on continue
    }
}

# Comptes locaux
$LocalUsers = Get-LocalUser
foreach ($user in $LocalUsers) {
    $statusU = "INFO"
    $detail  = ""

    if ($user.Enabled -and $user.Name -eq "Administrator") {
        $statusU = "WARN"; $detail = "Le compte Administrator intégré est activé"
    }
    if ($user.Enabled -and $user.PasswordNeverExpires) {
        $statusU = "WARN"; $detail += " | Mot de passe n'expire jamais"
    }
    if ($user.Enabled -and (-not $user.PasswordRequired)) {
        # NOTE v1.1 : ce flag SAM (UF_PASSWD_NOTREQD) peut être positionné
        # automatiquement par Windows Hello (PIN/biométrie) sans que ça
        # signifie qu'aucune authentification n'est requise à l'ouverture de
        # session. On le redescend en WARN (au lieu de FAIL).
        # NOTE v2.0 : on s'appuie désormais sur la détection Hello ci-dessus
        # pour donner une explication concrète plutôt qu'une simple piste de
        # vérification manuelle.
        $statusU = "WARN"
        if ($HelloConfigured) {
            $detail += " | Le SAM indique 'mot de passe non requis', mais un identifiant Windows Hello (PIN/biométrie) est enregistré sur ce poste — c'est probablement l'explication, pas une faille active"
        } elseif ($HelloIndeterminate) {
            $detail += " | Le SAM indique 'mot de passe non requis' — la détection Windows Hello n'a pas pu accéder à certains conteneurs protégés par le système pour confirmer ou infirmer, vérifie avec 'net user $($user.Name)' ou dans Paramètres > Comptes > Options de connexion"
        } else {
            $detail += " | Le SAM indique 'mot de passe non requis' et aucun identifiant Windows Hello n'a été détecté sur ce poste — vérifie avec 'net user $($user.Name)' si c'est un réglage réel à corriger"
        }
    }
    if (-not $user.Enabled) { $statusU = "INFO" }

    Add-Result "Comptes" "Utilisateur local : $($user.Name)" $(
        "$(if($user.Enabled){'Activé'}else{'Désactivé'}) | Pwd expire: $(if($user.PasswordNeverExpires){'Jamais'}else{'Oui'})"
    ) $statusU $detail
}

# Membres du groupe Administrateurs locaux
# NOTE v1.1 : l'ancienne version interrogeait le groupe par son nom anglais
# "Administrators", qui peut échouer silencieusement sur un Windows localisé
# (groupe nommé "Administrateurs" en interne) — l'erreur était avalée par
# -ErrorAction SilentlyContinue et le script affichait "OK" avec une valeur
# vide. On interroge maintenant par SID universel (S-1-5-32-544, valable sur
# toutes les langues) et on remonte clairement un échec de lecture le cas échéant.
try {
    $AdminGroup = Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop
    Add-Result "Comptes" "Membres Administrateurs locaux" ($AdminGroup.Name -join ", ") $(
        if ($AdminGroup.Count -gt 3) { "WARN" } else { "OK" }
    ) $(if($AdminGroup.Count -gt 3){"Trop de comptes administrateurs locaux"})
} catch {
    Add-Result "Comptes" "Membres Administrateurs locaux" "Lecture impossible" "WARN" "Erreur : $($_.Exception.Message)"
}

# NOTE v5.0 : compte Administrator intégré (RID-500) — sur un poste personnel
# hors domaine, ce compte doit rester désactivé. Activé, il offre une cible
# brute-force avec un nom prévisible (Administrator/Administrateur).
# Le SID se termine toujours en -500 quelle que soit la langue du système.
try {
    $AllLocalUsers = Get-LocalUser -ErrorAction Stop
    $BuiltinAdmin = $AllLocalUsers | Where-Object {
        $_.SID -and $_.SID.Value -match '-500$'
    } | Select-Object -First 1

    if ($BuiltinAdmin) {
        if ($BuiltinAdmin.Enabled) {
            Add-Result "Comptes" "Compte Administrateur intégré (RID-500)" "Activé — $($BuiltinAdmin.Name)" "WARN" "Le compte Administrateur intégré est actif. Sur un poste personnel hors domaine, le désactiver réduit la surface d'attaque brute-force locale : 'Disable-LocalUser -SID S-1-5-21-*-500' ou via lusrmgr.msc"
        } else {
            Add-Result "Comptes" "Compte Administrateur intégré (RID-500)" "Désactivé — $($BuiltinAdmin.Name)" "OK" "Le compte Administrateur intégré est correctement désactivé"
        }
    } else {
        Add-Result "Comptes" "Compte Administrateur intégré (RID-500)" "Non détecté" "INFO" "Aucun compte local avec SID se terminant en -500 — configuration inhabituelle"
    }
} catch {
    Add-Result "Comptes" "Compte Administrateur intégré (RID-500)" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
}

# Politique de mot de passe
# NOTE v1.1 : l'ancienne version parsait le texte de "net accounts", qui est
# localisé (français sur ce poste) — les libellés anglais ne matchaient jamais,
# d'où l'erreur systématique. On lit désormais les valeurs numériques brutes
# via le provider ADSI WinNT, qui n'est pas affecté par la langue du système.
#
# NOTE v1.2 : le premier correctif liait l'objet sans suffixe de classe
# ("WinNT://$env:COMPUTERNAME"), ce qui résout par défaut à la classe COM
# "Computer" — qui n'expose PAS MinPasswordLength/MaxPasswordAge/etc., d'où
# l'erreur "Object reference not set" en tentant d'y accéder. Sur un poste
# non joint à un domaine, ces propriétés de politique de mot de passe sont
# exposées via l'interface IADsDomain, qu'on obtient en liant explicitement
# avec le suffixe ",Domain". MaxPasswordAge est en plus un IADsLargeInteger
# (HighPart/LowPart), pas un entier simple — il faut le reconstituer à la main.
function Convert-AdsiLargeInteger {
    param($LargeInteger)
    if ($null -eq $LargeInteger) { return 0 }
    try {
        return [int64]([int64]$LargeInteger.HighPart * 4294967296) + [int64]$LargeInteger.LowPart
    } catch {
        return 0
    }
}

try {
    $ADSIComputer      = [ADSI]"WinNT://$env:COMPUTERNAME,Domain"
    $MinPwdLen         = [int]$ADSIComputer.MinPasswordLength
    $LockoutThreshold  = [int]$ADSIComputer.MaxBadPasswordsAllowed
    $MaxPwdAgeSeconds  = Convert-AdsiLargeInteger $ADSIComputer.MaxPasswordAge
    $MaxPwdAgeDays     = if ($MaxPwdAgeSeconds -gt 0) { [math]::Round($MaxPwdAgeSeconds / 86400) } else { 0 }
    # NOTE v3.0 : MinPasswordAge (délai avant de pouvoir rechanger un mot de
    # passe) et LockoutDuration (durée de blocage après dépassement du seuil
    # ci-dessous) — même provider ADSI déjà ouvert, aucun appel supplémentaire.
    $MinPwdAgeSeconds  = Convert-AdsiLargeInteger $ADSIComputer.MinPasswordAge
    $MinPwdAgeDays     = if ($MinPwdAgeSeconds -gt 0) { [math]::Round($MinPwdAgeSeconds / 86400) } else { 0 }
    $LockoutDurSeconds = Convert-AdsiLargeInteger $ADSIComputer.AutoUnlockInterval
    $LockoutDurMinutes = if ($LockoutDurSeconds -gt 0) { [math]::Round($LockoutDurSeconds / 60) } else { 0 }

    Add-Result "Politique MDP" "Longueur minimale exigée par la politique locale" "$MinPwdLen caractères" $(
        if ($MinPwdLen -lt 8) { "WARN" } elseif ($MinPwdLen -lt 12) { "WARN" } else { "OK" }
    ) "Ne reflète PAS ton mot de passe actuel : indique seulement la longueur minimale que Windows imposerait si le mot de passe d'un compte local était changé. Tu peux avoir un mot de passe fort déjà en place malgré un réglage permissif ici. Recommandé : ≥ 12"

    Add-Result "Politique MDP" "Âge maximum du mot de passe" $(
        if ($MaxPwdAgeDays -eq 0) { "Illimité" } else { "$MaxPwdAgeDays jours" }
    ) "INFO"

    Add-Result "Politique MDP" "Âge minimum du mot de passe" "$MinPwdAgeDays jour(s)" "INFO" "Délai minimum avant de pouvoir rechanger de mot de passe — réglage de politique, sans rapport avec le mot de passe actuel"

    Add-Result "Politique MDP" "Seuil de verrouillage" $(
        if ($LockoutThreshold -eq 0) { "Désactivé (0 tentative)" } else { "$LockoutThreshold tentatives" }
    ) $(
        if ($LockoutThreshold -eq 0) { "WARN" } else { "OK" }
    ) $(if($LockoutThreshold -eq 0){"Aucun verrouillage automatique après des tentatives de connexion échouées (protection anti-brute-force absente) — réglage de politique, indépendant de la force de ton mot de passe actuel"})

    if ($LockoutThreshold -gt 0) {
        Add-Result "Politique MDP" "Durée de verrouillage" "$LockoutDurMinutes minute(s)" $(
            if ($LockoutDurMinutes -lt 5) { "WARN" } else { "OK" }
        ) $(if($LockoutDurMinutes -lt 5){"Durée de verrouillage très courte — facilite les tentatives répétées de force brute par petites salves"})
    }
} catch {
    Add-Result "Politique MDP" "Lecture politique" "Erreur : $($_.Exception.Message)" "WARN"
}

# ──────────────────────────────────────────────
#  6. UAC (CONTRÔLE DE COMPTE UTILISATEUR)
# ──────────────────────────────────────────────
Write-Log "=== 6. UAC ===" -Level SECTION

$UACKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$EnableLUA        = (Get-ItemProperty $UACKey -Name "EnableLUA"        -EA SilentlyContinue).EnableLUA
$ConsentPrompt    = (Get-ItemProperty $UACKey -Name "ConsentPromptBehaviorAdmin" -EA SilentlyContinue).ConsentPromptBehaviorAdmin
$SecureDesktop    = (Get-ItemProperty $UACKey -Name "PromptOnSecureDesktop" -EA SilentlyContinue).PromptOnSecureDesktop

Add-Result "UAC" "UAC activé (EnableLUA)" $(if($EnableLUA -eq 1){"Oui"}else{"NON"}) $(if($EnableLUA -eq 1){"OK"}else{"FAIL"}) $(if($EnableLUA -ne 1){"UAC désactivé — risque critique !"})
Add-Result "UAC" "Niveau consentement admin" $ConsentPrompt $(
    if ($ConsentPrompt -eq 0) { "FAIL" } elseif ($ConsentPrompt -le 2) { "WARN" } else { "OK" }
) "0=Pas de prompt(dangereux), 2=Prompt creds, 5=Prompt (défaut)"
Add-Result "UAC" "Bureau sécurisé (SecureDesktop)" $(if($SecureDesktop -eq 1){"Activé"}else{"Désactivé"}) $(if($SecureDesktop -eq 1){"OK"}else{"WARN"})

# ──────────────────────────────────────────────
#  7. BITLOCKER
# ──────────────────────────────────────────────
Write-Log "=== 7. BITLOCKER ===" -Level SECTION

try {
    $Volumes = Get-BitLockerVolume -ErrorAction Stop
    foreach ($vol in $Volumes) {
        $isSystemVol = ("$($vol.MountPoint)".TrimEnd('\') -eq $env:SystemDrive)
        $st = switch ($vol.ProtectionStatus) {
            "On"  { "OK" }
            "Off" { if ($isSystemVol) { "FAIL" } else { "WARN" } }
            default { "WARN" }
        }
        $detailMsg = if ($vol.ProtectionStatus -ne "On") {
            if ($isSystemVol) {
                "Volume système non chiffré — données exposées en cas de vol/perte de la machine !"
            } else {
                "Volume de données non chiffré — WARN si ce volume contient des données sensibles ; acceptable si c'est un disque de jeux, une partition technique ou un choix volontaire"
            }
        }
        Add-Result "BitLocker" "Volume $($vol.MountPoint)" "Protection: $($vol.ProtectionStatus) | Chiffrement: $($vol.EncryptionPercentage)%" $st $detailMsg
    }
} catch {
    Add-Result "BitLocker" "BitLocker" "Non disponible ou erreur : $_" "WARN"
}

# ──────────────────────────────────────────────
#  8. PROTOCOLES RÉSEAU CRITIQUES
# ──────────────────────────────────────────────
Write-Log "=== 8. PROTOCOLES RÉSEAU ===" -Level SECTION

# SMBv1
try {
    $SMBv1 = Get-SmbServerConfiguration -ErrorAction Stop
    Add-Result "Réseau" "SMBv1 activé" $(if($SMBv1.EnableSMB1Protocol){"OUI — DANGEREUX"}else{"Non (correct)"}) $(
        if ($SMBv1.EnableSMB1Protocol) { "FAIL" } else { "OK" }
    ) $(if($SMBv1.EnableSMB1Protocol){"SMBv1 doit être désactivé (WannaCry, NotPetya…)"})

    # NOTE v3.0 : signature SMB — empêche le relais NTLM / la falsification de
    # paquets SMB en transit. RequireSecuritySignature côté serveur ET côté
    # client (Get-SmbClientConfiguration) sont deux réglages indépendants.
    Add-Result "Réseau" "Signature SMB requise (serveur)" $(if($SMBv1.RequireSecuritySignature){"Oui"}else{"Non"}) $(
        if ($SMBv1.RequireSecuritySignature) { "OK" } else { "WARN" }
    ) $(if(-not $SMBv1.RequireSecuritySignature){"La signature SMB n'est pas exigée côté serveur — expose à une attaque par relais/falsification SMB"})
} catch {
    Add-Result "Réseau" "SMBv1" "Erreur lecture" "WARN"
}

try {
    $SMBClient = Get-SmbClientConfiguration -ErrorAction Stop
    Add-Result "Réseau" "Signature SMB requise (client)" $(if($SMBClient.RequireSecuritySignature){"Oui"}else{"Non"}) $(
        if ($SMBClient.RequireSecuritySignature) { "OK" } else { "WARN" }
    ) $(if(-not $SMBClient.RequireSecuritySignature){"La signature SMB n'est pas exigée côté client — ce poste accepterait une connexion à un partage sans signature"})
} catch {
    Add-Result "Réseau" "Signature SMB (client)" "Erreur lecture" "INFO"
}

# NOTE v3.0 : restrictions NTLM — LmCompatibilityLevel pilote les versions de
# l'authentification NTLM acceptées. Niveau < 3 autorise LM/NTLMv1 (cassables
# en quelques secondes/minutes par les outils actuels) ; niveau 5 = refuse
# LM/NTLMv1 et n'accepte que NTLMv2. Clé absente = valeur par défaut Windows
# (3), affichée comme telle plutôt que comme une erreur.
$LmCompatKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$LmCompatRaw = (Get-ItemProperty $LmCompatKey -Name LmCompatibilityLevel -EA SilentlyContinue).LmCompatibilityLevel
$LmCompatLevel = if ($null -ne $LmCompatRaw) { [int]$LmCompatRaw } else { 3 }
$LmCompatLabel = switch ($LmCompatLevel) {
    0 { "0 — LM et NTLMv1 envoyés, jamais NTLMv2 (très permissif)" }
    1 { "1 — LM/NTLMv1, NTLMv2 si négocié" }
    2 { "2 — NTLMv1 uniquement" }
    3 { "3 — NTLMv2 uniquement (défaut Windows)" }
    4 { "4 — NTLMv2 uniquement, refuse LM entrant" }
    5 { "5 — NTLMv2 uniquement, refuse LM et NTLM entrants (le plus strict)" }
    default { "$LmCompatLevel — valeur non standard" }
}
Add-Result "Réseau" "Restriction NTLM (LmCompatibilityLevel)" $LmCompatLabel $(
    if ($LmCompatLevel -le 1) { "FAIL" } elseif ($LmCompatLevel -le 2) { "WARN" } else { "OK" }
) $(if($LmCompatLevel -le 2){"Ce niveau autorise NTLMv1/LM, cassables rapidement par les outils actuels — relever à 5 si aucun équipement legacy n'en dépend"})

# NOTE v3.0 : DNS chiffré (DoH) au niveau système — Erwan utilise déjà NextDNS
# en app dédiée, donc ce contrôle vérifie surtout que le résolveur Windows
# natif (au cas où l'app NextDNS serait arrêtée) n'expose pas les requêtes en
# clair. DohFlag : 0=désactivé, 1=autorisé, 2=requis pour les serveurs DoH connus, 3=requis pour tous.
try {
    $DnsInterfaces = Get-DnsClientDohServerAddress -ErrorAction Stop
    if ($DnsInterfaces) {
        $DohActive = $DnsInterfaces | Where-Object { $_.DohFlag -ge 1 }
        Add-Result "Réseau" "DNS chiffré (DoH)" $(if($DohActive){"$($DohActive.Count) serveur(s) DoH configuré(s)"}else{"Aucun serveur DoH configuré"}) $(
            if ($DohActive) { "OK" } else { "INFO" }
        ) "Vérifie surtout la résolution DNS du système en dehors de NextDNS (app dédiée) — les requêtes DNS classiques (port 53) circulent en clair"
    } else {
        Add-Result "Réseau" "DNS chiffré (DoH)" "Aucun serveur DoH configuré" "INFO" "Les requêtes DNS système circulent en clair sauf si filtrées en amont (ex : NextDNS, si actif)"
    }
} catch {
    Add-Result "Réseau" "DNS chiffré (DoH)" "Non disponible sur cette build" "INFO"
}

# RDP
$RDPKey = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
$RDPEnabled = (Get-ItemProperty $RDPKey -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections
Add-Result "Réseau" "RDP activé" $(if($RDPEnabled -eq 0){"OUI"}else{"Non"}) $(
    if ($RDPEnabled -eq 0) { "WARN" } else { "OK" }
) $(if($RDPEnabled -eq 0){"RDP actif — vérifier NLA et règles pare-feu"})

# NLA pour RDP
if ($RDPEnabled -eq 0) {
    $NLA = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -EA SilentlyContinue).UserAuthentication
    Add-Result "Réseau" "NLA (Network Level Auth) RDP" $(if($NLA -eq 1){"Activé"}else{"DÉSACTIVÉ"}) $(
        if ($NLA -eq 1) { "OK" } else { "FAIL" }
    ) $(if($NLA -ne 1){"NLA désactivé sur RDP — authentification non sécurisée"})
}

# NOTE v4.0 : connexions TCP établies vers l'extérieur enrichies avec le nom
# du processus. Croisement sur OwningProcess (PID) -> Get-Process. Les adresses
# loopback (127.x, ::1) et link-local IPv6 (fe80::) sont filtrées. Un PID
# non résolvable (process terminé entre la lecture de la socket et Get-Process,
# ou service SYSTEM non lisible) génère un WARN — signe d'un comportement
# inhabituel ou d'une race condition bénigne à vérifier.
try {
    $ExtConns = Get-NetTCPConnection -State Established -ErrorAction Stop |
        Where-Object {
            $_.RemoteAddress -ne "127.0.0.1" -and
            $_.RemoteAddress -ne "::1" -and
            $_.RemoteAddress -notmatch "^fe80:" -and
            $_.RemoteAddress -ne "0.0.0.0"
        }

    if ($ExtConns.Count -eq 0) {
        Add-Result "Réseau" "Connexions TCP établies (extérieures)" "0" "OK" "Aucune connexion TCP établie vers l'extérieur au moment de l'audit"
    } else {
        # Construire une table PID -> nom de processus en une seule requête
        # (évite N appels Get-Process dans la boucle)
        $ProcMap = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $ProcMap[$_.Id] = $_.Name }

        $ConnOrphans  = [System.Collections.Generic.List[string]]::new()
        $ConnDetails  = [System.Collections.Generic.List[string]]::new()

        foreach ($c in ($ExtConns | Select-Object -First 30)) {
            $procId = $c.OwningProcess
            $proc = if ($ProcMap.ContainsKey([int]$procId)) { $ProcMap[[int]$procId] } else { $null }
            if ($proc) {
                $ConnDetails.Add("$proc (PID $procId) → $($c.RemoteAddress):$($c.RemotePort)")
            } else {
                $ConnOrphans.Add("PID $procId → $($c.RemoteAddress):$($c.RemotePort)")
            }
        }

        $totalShown = [math]::Min(30, $ExtConns.Count)
        $truncNote  = if ($ExtConns.Count -gt 30) { " (affichage limité aux 30 premières sur $($ExtConns.Count))" } else { "" }

        Add-Result "Réseau" "Connexions TCP établies (extérieures)" "$($ExtConns.Count) connexion(s)$truncNote" "INFO" ($ConnDetails -join " | ")

        if ($ConnOrphans.Count -gt 0) {
            Add-Result "Réseau" "Connexions TCP — processus non résolvable" "$($ConnOrphans.Count) socket(s)" "WARN" "PID actif à la création de la socket mais non résolvable au moment de l'audit (process terminé en cours d'exécution, ou service SYSTEM sans accès) : $($ConnOrphans -join ' | ')"
        }

        # NOTE v5.0 : résumé des connexions vers IPs publiques (non-RFC1918).
        # On sépare les connexions vers des IPs privées (192.168.x, 10.x, 172.16-31.x)
        # des connexions vers des IPs publiques réelles. Les IPs publiques méritent
        # une attention particulière : c'est là que passe le trafic légitime (CDN,
        # APIs) mais aussi potentiellement du C&C ou de l'exfiltration.
        # Liste blanche des processus système attendus à avoir des connexions publiques.
        # NOTE v5.0.1 : ajouts post-run NEPH-DESKTOP — processus légitimes
        # signalés en WARN car absents de la liste initiale.
        # NextDNSService : proxy DNS DoH local (NextDNS). MpDefenderCoreService :
        # composant Defender (protection cloud/telemetry). Rainmeter : widget bureau.
        # NOTE v5.0.2 : pwsh/powershell — le script lui-même (ou une session PS
        # ouverte en parallèle) peut avoir une connexion TCP publique active au
        # moment de l'audit (requête Update/Gallery, session ouverte, etc.).
        $SystemProcsAllowlist = @("svchost","SearchApp","MicrosoftEdge","msedge","brave",
            "chrome","firefox","librewolf","Spotify","steam","OneDrive","MsMpEng",
            "WinStore.App","SystemSettings","WidgetService","explorer","backgroundTaskHost",
            "NextDNSService","MpDefenderCoreService","MpDefenderCore","Rainmeter",
            "NisSrv","SecurityHealthService","SgrmBroker","spoolsv","lsass","wininit",
            "pwsh","powershell","powershell_ise")

        $PublicConns = $ExtConns | Where-Object {
            $addr = $_.RemoteAddress
            # Exclure RFC-1918 + link-local + APIPA
            -not ($addr -match '^10\.' -or
                  $addr -match '^192\.168\.' -or
                  $addr -match '^172\.(1[6-9]|2[0-9]|3[01])\.' -or
                  $addr -match '^169\.254\.' -or
                  $addr -match '^fc|^fd' -or
                  $addr -eq '::')
        }

        if ($PublicConns.Count -gt 0) {
            $PubKnown   = [System.Collections.Generic.List[string]]::new()
            $PubUnknown = [System.Collections.Generic.List[string]]::new()

            foreach ($pc in ($PublicConns | Select-Object -First 20)) {
                $procName = if ($ProcMap.ContainsKey([int]$pc.OwningProcess)) { $ProcMap[[int]$pc.OwningProcess] } else { "PID $($pc.OwningProcess)" }
                $entry = "$procName → $($pc.RemoteAddress):$($pc.RemotePort)"
                $isKnown = $false
                foreach ($sp in $SystemProcsAllowlist) {
                    if ($procName -like "*$sp*") { $isKnown = $true; break }
                }
                if ($isKnown) { $PubKnown.Add($entry) } else { $PubUnknown.Add($entry) }
            }

            $pubStatus = if ($PubUnknown.Count -gt 0) { "WARN" } else { "INFO" }
            $pubDetail = ""
            if ($PubUnknown.Count -gt 0) { $pubDetail += "⚠ Processus non reconnus vers IPs publiques : $($PubUnknown -join ' | ') " }
            if ($PubKnown.Count -gt 0)   { $pubDetail += "✓ Processus reconnus : $($PubKnown -join ' | ')" }
            Add-Result "Réseau" "Connexions TCP vers IPs publiques" "$($PublicConns.Count) connexion(s)" $pubStatus $pubDetail
        } else {
            Add-Result "Réseau" "Connexions TCP vers IPs publiques" "0" "OK" "Aucune connexion TCP établie vers des IPs publiques au moment de l'audit"
        }
    }
} catch {
    # NOTE v4.1 : Get-NetTCPConnection peut échouer sur certains sockets
    # système même en admin (notamment les sockets héritant d'un contexte
    # de session différent). Ce n'est pas une anomalie de sécurité —
    # downgradé en INFO pour ne pas polluer le score Réseau.
    $errMsg = $_.Exception.Message
    Add-Result "Réseau" "Connexions TCP établies (extérieures)" "Lecture impossible" "INFO" "Erreur lors de l'énumération des sockets TCP : $errMsg — ce n'est pas une anomalie de sécurité (limitation d'accès aux sockets système)"
}

# Partages réseau
$Shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$' }
Add-Result "Réseau" "Partages réseau non-admin" $Shares.Count $(
    if ($Shares.Count -gt 0) { "WARN" } else { "OK" }
) $(if($Shares.Count -gt 0){"Partages détectés : " + ($Shares.Name -join ", ")})

# NOTE v4.2 : WinRM (Windows Remote Management / accès PS distant).
# WinRM actif permet à tout administrateur d'ouvrir une session PowerShell
# distante sur ce poste (Enter-PSSession, Invoke-Command). Sur un PC perso
# hors domaine, ce service n'a aucune raison d'être actif. On vérifie deux
# choses : le statut du service, ET la présence d'un listener WSMan dans le
# registre (un listener peut survivre à un service arrêté et se réactiver).
try {
    $WinRMSvc = Get-Service -Name WinRM -ErrorAction Stop
    $WinRMListenerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener"
    $WinRMListeners = if (Test-Path -LiteralPath $WinRMListenerKey -ErrorAction SilentlyContinue) {
        Get-ChildItem -Path $WinRMListenerKey -ErrorAction SilentlyContinue
    } else { @() }

    if ($WinRMSvc.Status -eq "Running") {
        $listenerDetail = if ($WinRMListeners.Count -gt 0) {
            "Listeners configurés : " + ($WinRMListeners | ForEach-Object { $_.PSChildName } | Join-String -Separator ", ")
        } else { "Aucun listener WSMan détecté malgré le service actif" }
        Add-Result "Réseau" "WinRM (accès PS distant)" "Service ACTIF ($($WinRMSvc.StartType))" "WARN" "WinRM en cours d'exécution — permet l'accès PowerShell distant. Sur un poste personnel hors domaine, désactiver via : Stop-Service WinRM ; Set-Service WinRM -StartupType Disabled. $listenerDetail"
    } elseif ($WinRMListeners.Count -gt 0) {
        Add-Result "Réseau" "WinRM (accès PS distant)" "Service arrêté mais listener(s) WSMan présent(s)" "WARN" "Le service WinRM est arrêté mais $($WinRMListeners.Count) listener(s) WSMan sont configurés dans le registre — WinRM peut être réactivé automatiquement par certains outils. Supprimer les listeners si non intentionnel."
    } else {
        Add-Result "Réseau" "WinRM (accès PS distant)" "Désactivé (service $($WinRMSvc.Status), aucun listener)" "OK" "Aucun accès PowerShell distant possible"
    }
} catch {
    Add-Result "Réseau" "WinRM (accès PS distant)" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
}

# NOTE v4.2 : profil réseau actif par interface. Get-NetConnectionProfile retourne
# le profil de chaque interface connectée (Public, Private, Domain). Un profil
# Domain sur un poste WORKGROUP est une config orpheline — peut résulter d'une
# ancienne jonction de domaine ou d'une manipulation manuelle, et affecte les
# règles de pare-feu appliquées à cette interface.
try {
    $NetProfiles = Get-NetConnectionProfile -ErrorAction Stop
    foreach ($np in $NetProfiles) {
        $profileLabel = "$($np.NetworkCategory) — réseau : $($np.Name)"
        $isOrphanDomain = ($np.NetworkCategory -eq "DomainAuthenticated") -and ($env:USERDNSDOMAIN -eq $env:COMPUTERNAME -or $env:USERDOMAIN -eq $env:COMPUTERNAME)
        $status = if ($isOrphanDomain) { "WARN" } else { "INFO" }
        $detail = if ($isOrphanDomain) {
            "Profil Domain sur un poste hors domaine — config orpheline possible. Règles pare-feu du profil Domain appliquées, potentiellement plus permissives."
        } else { "" }
        Add-Result "Réseau" "Profil réseau : $($np.InterfaceAlias)" $profileLabel $status $detail
    }
} catch {
    Add-Result "Réseau" "Profils réseau par interface" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
}

# NOTE v5.0 : IPv6 exposition pare-feu — un poste avec IPv6 actif sur une
# interface publique mais sans règles de blocage entrantes dédiées en IPv6
# laisse un angle mort. Les règles de pare-feu Windows sont partagées IPv4/IPv6
# par défaut pour les règles "Any", mais certains admins créent des règles
# explicitement liées à des adresses IPv4 qui ne couvrent pas IPv6.
# On vérifie : IPv6 actif sur ≥1 interface non-loopback ET pare-feu Public
# en mode Block par défaut pour les connexions entrantes.
try {
    $IPv6Adapters = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop |
        Where-Object { $_.Enabled -eq $true }

    $ActiveIPv6 = $IPv6Adapters | Where-Object {
        # Filtrer loopback et interfaces virtuelles sans trafic réel
        $_.Name -notmatch "Loopback|Local Area Connection\* \d+|isatap|teredo" -and
        (Get-NetAdapter -Name $_.Name -ErrorAction SilentlyContinue).Status -eq "Up"
    }

    if ($ActiveIPv6.Count -eq 0) {
        Add-Result "Réseau" "IPv6 actif sur interfaces réseau" "Non actif sur interfaces UP" "INFO" "IPv6 désactivé ou inactif sur toutes les interfaces connectées — aucun angle mort pare-feu IPv6"
    } else {
        # Vérifier que le pare-feu couvre bien le profil Public en blocage entrant
        $FwPublicProfile = Get-NetFirewallProfile -Name Public -ErrorAction SilentlyContinue
        # NOTE v5.0.1 : NotConfigured = Windows Defender Firewall applique sa
        # politique par défaut (blocage entrant sur le profil Public) — ce n'est
        # pas une absence de protection, c'est le comportement normal sur Win11.
        # La v5.0 ne testait que "Block" explicite → faux positif systématique
        # sur tous les postes Win11 avec profil Public en configuration par défaut.
        $inboundBlocked = $FwPublicProfile -and (
            $FwPublicProfile.DefaultInboundAction -eq "Block" -or
            $FwPublicProfile.DefaultInboundAction -eq "NotConfigured"
        )

        $ifNames = ($ActiveIPv6.Name) -join ", "
        if ($inboundBlocked) {
            Add-Result "Réseau" "IPv6 actif (interfaces UP)" "$($ActiveIPv6.Count) interface(s) : $ifNames" "OK" "IPv6 actif mais le profil Public bloque les connexions entrantes par défaut — les règles de pare-feu s'appliquent aussi aux connexions IPv6 entrantes"
        } else {
            Add-Result "Réseau" "IPv6 actif (interfaces UP)" "$($ActiveIPv6.Count) interface(s) : $ifNames" "WARN" "IPv6 actif sur $($ActiveIPv6.Count) interface(s) et le profil Public n'est pas en blocage entrant par défaut — vérifier que les règles entrantes du pare-feu couvrent aussi les adresses IPv6 (pas uniquement des plages IPv4 explicites)"
        }
    }
} catch {
    Add-Result "Réseau" "IPv6 actif (interfaces réseau)" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
}

# NOTE v4.7 : ports TCP en écoute sur interfaces non-loopback avec PID/processus.
# Complémentaire des connexions TCP établies — les ports en écoute représentent
# la surface d'attaque réseau exposée en permanence. On croise avec une liste de
# ports sensibles pour détecter immédiatement si RDP, WinRM, SMB, Telnet ou
# VNC sont en écoute sur une interface publique.
# NOTE v4.8 : classification affinée des ports en écoute par adresse locale.
# RPC 135 et SMB 445 écoutent sur toutes les interfaces sur toute machine
# Windows — c'est normal et ne mérite pas WARN. Ce qui mérite attention c'est
# un port en écoute sur 0.0.0.0 ou :: (toutes interfaces) — surtout RDP,
# WinRM, ou des ports applicatifs inconnus.
$SensitivePorts = @{
    3389="RDP"; 5985="WinRM-HTTP"; 5986="WinRM-HTTPS"
    23="Telnet"; 5900="VNC"; 21="FTP"; 22="SSH"
}
# Ports normaux sur Windows — INFO même sur 0.0.0.0
$NormalWindowsPorts = @(135, 445, 139, 49664, 49665, 49666, 49667, 49668, 49669, 49670)

try {
    $ListenConns = Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object {
            $_.LocalAddress -ne "127.0.0.1" -and
            $_.LocalAddress -ne "::1" -and
            $_.LocalAddress -notmatch "^fe80:"
        }

    if ($ListenConns.Count -eq 0) {
        Add-Result "Réseau" "Ports TCP en écoute (non-loopback)" "0" "OK" "Aucun port TCP en écoute sur les interfaces non-loopback"
    } else {
        $ProcMapListen = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $ProcMapListen[$_.Id] = $_.Name }

        $failPorts  = [System.Collections.Generic.List[string]]::new()
        $warnPorts  = [System.Collections.Generic.List[string]]::new()
        $infoPorts  = [System.Collections.Generic.List[string]]::new()

        foreach ($c in $ListenConns) {
            $procName  = if ($ProcMapListen.ContainsKey([int]$c.OwningProcess)) { $ProcMapListen[[int]$c.OwningProcess] } else { "PID $($c.OwningProcess)" }
            $portNum   = [int]$c.LocalPort
            $isAllIf   = ($c.LocalAddress -eq "0.0.0.0" -or $c.LocalAddress -eq "::")
            $isNormal  = $NormalWindowsPorts -contains $portNum
            $isSensitive = $SensitivePorts.ContainsKey($portNum)
            $portName  = if ($SensitivePorts.ContainsKey($portNum)) { $SensitivePorts[$portNum] } else { "$portNum" }
            $label     = "$procName → $portName ($($c.LocalAddress))"

            if ($isNormal) {
                $infoPorts.Add($label)
            } elseif ($isSensitive -and $isAllIf) {
                if ($portNum -eq 3389) { $failPorts.Add($label) }
                else { $warnPorts.Add($label) }
            } elseif ($isSensitive) {
                $warnPorts.Add($label)
            } elseif ($isAllIf -and $portNum -lt 1024) {
                $warnPorts.Add($label)
            } else {
                $infoPorts.Add($label)
            }
        }

        $overallStatus = if ($failPorts.Count -gt 0) { "FAIL" } elseif ($warnPorts.Count -gt 0) { "WARN" } else { "INFO" }
        $detail = ""
        if ($failPorts.Count -gt 0) { $detail += "❌ Ports critiques exposés : $($failPorts -join ' | ') " }
        if ($warnPorts.Count -gt 0) { $detail += "⚠ Ports sensibles : $($warnPorts -join ' | ') " }
        if ($infoPorts.Count -gt 0) { $detail += "Ports normaux/système : $($infoPorts -join ' | ')" }

        Add-Result "Réseau" "Ports TCP en écoute (non-loopback)" "$($ListenConns.Count) port(s)" $overallStatus $detail.Trim()
    }
} catch {
    Add-Result "Réseau" "Ports TCP en écoute (non-loopback)" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
}

# ──────────────────────────────────────────────
#  9. SERVICES CRITIQUES / SUSPECTS
# ──────────────────────────────────────────────
Write-Log "=== 9. SERVICES ===" -Level SECTION

$CriticalServices = @(
    @{ Name="WinDefend";   Friendly="Windows Defender Antivirus";     Expected="Running" },
    @{ Name="MpsSvc";      Friendly="Pare-feu Windows";               Expected="Running" },
    @{ Name="EventLog";    Friendly="Journal des événements";         Expected="Running" },
    @{ Name="wuauserv";    Friendly="Windows Update";                 Expected="Running" },
    @{ Name="CryptSvc";    Friendly="Services de chiffrement";        Expected="Running" },
    @{ Name="BFE";         Friendly="Base Filtering Engine";          Expected="Running" }
)

foreach ($svc in $CriticalServices) {
    $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($s) {
        # NOTE v1.3 : l'ancienne version attendait "Running" pour tous ces
        # services sans distinction, ce qui faisait FAIL Windows Update (wuauserv)
        # dès qu'il était arrêté — alors qu'un service en démarrage Manuel/Trigger
        # (normal pour wuauserv sur Windows moderne) est censé rester arrêté tant
        # qu'il n'est pas sollicité. Seul un service Disabled, ou un service
        # Automatic qui ne tourne pas, est une vraie anomalie.
        if ($s.StartType -eq "Disabled") {
            Add-Result "Services" $svc.Friendly "$($s.Status) (Démarrage: $($s.StartType))" "FAIL" "Service $($svc.Name) désactivé !"
        } elseif ($s.StartType -eq "Manual" -and $s.Status -ne "Running") {
            Add-Result "Services" $svc.Friendly "$($s.Status) (Démarrage: $($s.StartType))" "INFO" "Démarrage Manuel/à la demande — normal que le service soit arrêté hors utilisation"
        } else {
            $st = if ($s.Status -eq $svc.Expected) { "OK" } else { "FAIL" }
            Add-Result "Services" $svc.Friendly "$($s.Status) (Démarrage: $($s.StartType))" $st $(
                if ($s.Status -ne $svc.Expected) { "Service $($svc.Name) arrêté ou désactivé !" }
            )
        }
    } else {
        Add-Result "Services" $svc.Friendly "Non trouvé" "WARN"
    }
}

# Services non-Microsoft en démarrage automatique
# NOTE v1.1 : Get-WmiObject a été retiré de PowerShell 7+ ; Get-CimInstance
# est l'équivalent moderne, compatible PS 5.1 et PS7.
# NOTE v4.7 : services non-Microsoft en démarrage automatique — on affiche
# maintenant le nom, DisplayName et chemin de chaque service tiers pour
# permettre une vérification rapide. WARN si un chemin est hors des zones
# de confiance (System32, Program Files) ou si le compte de service est
# un compte utilisateur (pas SYSTEM/LocalService/NetworkService).
$SuspiciousServices = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
    Where-Object {
        $_.StartMode -eq "Auto" -and
        $_.State    -eq "Running" -and
        $_.PathName -notmatch "system32|SysWOW64|Microsoft|Windows"
    } | Select-Object Name, DisplayName, PathName, StartName

$svcSuspect = [System.Collections.Generic.List[string]]::new()
$svcNormal  = [System.Collections.Generic.List[string]]::new()

foreach ($svc in $SuspiciousServices) {
    # NOTE v4.8.1 : le nettoyage précédent (-replace '"','' -replace ' .*$','')
    # tronquait "C:\Program Files\..." à "C:\Program" dès le premier espace,
    # rendant le match "program files" toujours faux. Nouveau comportement :
    # 1. Si le PathName commence par un guillemet, extraire le chemin entre
    #    les deux guillemets (chemin avec espaces possible).
    # 2. Sinon, couper au premier espace (chemin sans espace + arguments).
    $rawPath = $svc.PathName
    if ($rawPath -match '^"([^"]+)"') {
        $pathClean = $Matches[1]
    } else {
        $pathClean = ($rawPath -split ' ')[0]
    }

    $isSuspectPath  = $pathClean -notmatch "(?i)program files|programdata|appdata\\local\\programs|program files \(x86\)"
    $isSuspectAcct  = $svc.StartName -and $svc.StartName -notmatch "(?i)LocalSystem|LocalService|NetworkService|NT AUTHORITY|NT SERVICE"
    $label = "$($svc.Name) ($($svc.DisplayName)) — $pathClean"
    if ($isSuspectPath -or $isSuspectAcct) {
        $svcSuspect.Add($label)
    } else {
        $svcNormal.Add($label)
    }
}

$svcStatus = if ($svcSuspect.Count -gt 0) { "WARN" } elseif ($SuspiciousServices.Count -gt 10) { "WARN" } else { "INFO" }
$svcDetail = if ($svcSuspect.Count -gt 0) {
    "Services avec chemin/compte suspect : $($svcSuspect -join ' | ')$(if($svcNormal.Count -gt 0){" — Services tiers standard : $($svcNormal -join ' | ')"})"
} elseif ($SuspiciousServices.Count -gt 0) {
    "Services tiers en démarrage automatique (chemins standards) : $($svcNormal -join ' | ')"
} else {
    "Aucun service tiers en démarrage automatique"
}
Add-Result "Services" "Services auto non-système" $SuspiciousServices.Count $svcStatus $svcDetail

# ──────────────────────────────────────────────
#  10. JOURNAUX D'ÉVÉNEMENTS & AUDIT
# ──────────────────────────────────────────────
Write-Log "=== 10. JOURNAUX & AUDIT ===" -Level SECTION

# Politique d'audit
# NOTE v1.1 : l'ancienne version interrogeait auditpol par nom de catégorie
# anglais ("Logon", "Account Logon"...) et filtrait la sortie sur les mots
# "Success|Failure|No Auditing". Sur un Windows en français, ni le nom de
# catégorie ni les valeurs de réglage ("Succès"/"Échec") ne matchaient,
# d'où des résultats systématiquement vides. On interroge maintenant par
# GUID de catégorie (identique quelle que soit la langue du système) et on
# extrait les lignes de données par position plutôt que par mot-clé anglais.
# Les 3 premières lignes de sortie d'auditpol /get /category sont toujours
# des en-têtes (titre, ligne de colonnes, nom de catégorie) ; on les ignore.
$AuditCategoryMap = @(
    @{ Label = "Connexion (Logon/Logoff)";                   Guid = "{69979849-797A-11D9-BED3-505054503030}" },
    @{ Label = "Connexion de compte (Account Logon)";        Guid = "{69979850-797A-11D9-BED3-505054503030}" },
    @{ Label = "Accès aux objets (Object Access)";           Guid = "{6997984A-797A-11D9-BED3-505054503030}" },
    @{ Label = "Utilisation des privilèges (Privilege Use)"; Guid = "{6997984B-797A-11D9-BED3-505054503030}" },
    @{ Label = "Modification de stratégie (Policy Change)";  Guid = "{6997984D-797A-11D9-BED3-505054503030}" }
)

foreach ($cat in $AuditCategoryMap) {
    try {
        $raw = auditpol /get /category:"$($cat.Guid)" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "auditpol a renvoyé une erreur (code $LASTEXITCODE) : $($raw -join ' ')" }
        $dataLines = $raw | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }
        Add-Result "Audit" "Politique : $($cat.Label)" ($dataLines -join " / ") "INFO"
    } catch {
        Add-Result "Audit" "Politique : $($cat.Label)" "Lecture impossible" "WARN" "Erreur : $($_.Exception.Message). Vérifie les GUID avec 'auditpol /list /category /v' si ça persiste."
    }
}

# Événements de sécurité récents (échecs de connexion)
try {
    $FailedLogons = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4625
        StartTime = (Get-Date).AddHours(-24)
    } -MaxEvents 100 -ErrorAction SilentlyContinue

    Add-Result "Audit" "Échecs de connexion (24h)" $FailedLogons.Count $(
        if ($FailedLogons.Count -gt 50) { "FAIL" }
        elseif ($FailedLogons.Count -gt 10) { "WARN" }
        else { "OK" }
    ) $(if($FailedLogons.Count -gt 50){"Possible attaque par force brute !"})
} catch {
    Add-Result "Audit" "Échecs de connexion (24h)" "Accès refusé ou journal vide" "WARN"
}

# NOTE v4.2 : événements de sécurité supplémentaires sur les 24 dernières heures.
# Ces trois IDs sont absents des contrôles v3.x mais couvrent des vecteurs
# d'attaque réels sur un poste Windows autonome.
#
# 4648 — Ouverture de session avec credentials explicites (RunAs, net use /user,
# WMI distant, scripts qui appellent LogonUser()...). Quelques occurrences sont
# normales (certains services ou mises à jour les génèrent). Un pic soudain
# ou des comptes inhabituels dans les détails signalent une élévation de
# privilèges ou un mouvement latéral.
#
# 4720 / 4726 — Création / suppression de compte local. Sur un PC perso hors
# domaine sans activité d'administration récente, ces événements doivent être
# à 0. Un compte créé par un malware de type RAT ou un script d'accès de
# maintenance non autorisé passera ici.
$ExtraAuditEvents = @(
    @{ Id=4648; Label="Connexions avec credentials explicites (RunAs/net use)"; WarnThreshold=50 },
    @{ Id=4720; Label="Créations de compte local";                              WarnThreshold=1  },
    @{ Id=4726; Label="Suppressions de compte local";                           WarnThreshold=1  }
)
foreach ($evDef in $ExtraAuditEvents) {
    try {
        $evts = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = $evDef.Id
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 200 -ErrorAction SilentlyContinue
        $count = if ($null -eq $evts) { 0 } else { @($evts).Count }
        $status = if ($count -ge $evDef.WarnThreshold -and $evDef.WarnThreshold -eq 1 -and $count -gt 0) { "WARN" }
                  elseif ($count -gt $evDef.WarnThreshold) { "WARN" }
                  elseif ($count -gt 0) { "INFO" }
                  else { "OK" }
        $detail = if ($count -gt 0 -and $evDef.Id -eq 4648) {
            "Comptes cibles dans les $count événement(s) : " + (($evts | Select-Object -First 5 | ForEach-Object {
                try { $_.Properties[5].Value } catch { "?" }
            }) -join ", ") + $(if($count -gt 5){" …"})
        } elseif ($count -gt 0) {
            "Comptes concernés dans les $count événement(s) : " + (($evts | Select-Object -First 5 | ForEach-Object {
                try { $_.Properties[0].Value } catch { "?" }
            }) -join ", ") + $(if($count -gt 5){" …"})
        } else { "" }
        Add-Result "Audit" "$($evDef.Label) (24h)" $count $status $detail
    } catch {
        Add-Result "Audit" "$($evDef.Label) (24h)" "Non disponible" "INFO" "Journal Security inaccessible ou politique d'audit inactive pour cet événement : $($_.Exception.Message)"
    }
}

# Taille des journaux
$Logs = @("Security","System","Application")
foreach ($log in $Logs) {
    try {
        $wLog = Get-WinEvent -ListLog $log -ErrorAction Stop
        $sizeMB = [math]::Round($wLog.FileSize / 1MB, 2)
        Add-Result "Audit" "Journal $log (taille)" "${sizeMB} MB / Max: $([math]::Round($wLog.MaximumSizeInBytes/1MB,0)) MB" "INFO"
    } catch {}
}

# ──────────────────────────────────────────────
#  11. TÂCHES PLANIFIÉES SUSPECTES
# ──────────────────────────────────────────────
Write-Log "=== 11. TÂCHES PLANIFIÉES ===" -Level SECTION

# NOTE v1.1 : l'ancienne version flaguait toute tâche non-Microsoft lançant un
# interpréteur — ce qui inclut systématiquement tes propres scripts planifiés
# (Nettoyage-Windows11, Block-Telemetry, etc.). On exclut maintenant les tâches
# dont le script est signé par ton certificat personnel ($TrustedSignerSubjectMatch,
# défini en haut du script) ou se trouve sous un des $TrustedScriptPathPatterns.
$SuspTasksRaw = Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object {
        $_.State -eq "Ready" -and
        $_.TaskPath -notmatch "\\Microsoft\\" -and
        ($_.Actions | Where-Object { $_.Execute -match "powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32" })
    }

$SuspTasksReal    = [System.Collections.Generic.List[object]]::new()
$SuspTasksTrusted = [System.Collections.Generic.List[object]]::new()

foreach ($task in $SuspTasksRaw) {
    $isTrusted = $false

    # NOTE v3.3 — priorité 1 : correspondance par nom de tâche ($TrustedTaskNames).
    # Vérifié en premier car indépendant du format des arguments. Couvre les
    # tâches cmd, .bat, ou dont le chemin du script n'est pas extractible.
    if ($TrustedTaskNames -contains $task.TaskName) {
        $isTrusted = $true
    }

    if (-not $isTrusted) {
        foreach ($action in $task.Actions) {
            if ($isTrusted) { break }
            $argLine = "$($action.Execute) $($action.Arguments)"

            # NOTE v3.3 — priorité 2 : extraction du chemin .ps1.
            # Ancienne regex : [A-Za-z]:\\[^\s"]+\.ps1 — s'arrêtait au premier
            # espace, donc ne capturait jamais un chemin comme
            # "C:\Users\nephren\Desktop\Scripts Maintenance Win11\Script.ps1".
            # Nouvelle logique : on essaie d'abord le chemin entre guillemets
            # (qui peut contenir des espaces), puis le chemin sans guillemets
            # (sans espaces). Premier match retenu.
            $scriptPath = $null
            $quotedMatch   = [regex]::Match($argLine, '"([A-Za-z]:\\[^"]+\.ps1)"')
            $unquotedMatch = [regex]::Match($argLine,  '([A-Za-z]:\\[^\s"]+\.ps1)')
            if    ($quotedMatch.Success)   { $scriptPath = $quotedMatch.Groups[1].Value }
            elseif ($unquotedMatch.Success) { $scriptPath = $unquotedMatch.Groups[1].Value }
            if (-not $scriptPath) { continue }

            foreach ($pattern in $TrustedScriptPathPatterns) {
                if ($scriptPath -like $pattern) { $isTrusted = $true }
            }

            if (-not $isTrusted -and (Test-Path $scriptPath -ErrorAction SilentlyContinue)) {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $scriptPath -ErrorAction Stop
                    if ($sig.Status -eq "Valid" -and $sig.SignerCertificate.Subject -match [regex]::Escape($TrustedSignerSubjectMatch)) {
                        $isTrusted = $true
                    }
                } catch {}
            }
        }
    }

    if ($isTrusted) { $SuspTasksTrusted.Add($task) } else { $SuspTasksReal.Add($task) }
}

Add-Result "Tâches planifiées" "Tâches non-Microsoft avec scripts/interpréteurs (non reconnues)" $SuspTasksReal.Count $(
    if ($SuspTasksReal.Count -gt 5) { "WARN" } elseif ($SuspTasksReal.Count -gt 0) { "WARN" } else { "OK" }
) $(if($SuspTasksReal.Count -gt 0){"Tâches à auditer : " + ($SuspTasksReal.TaskName -join ", ")})

if ($SuspTasksTrusted.Count -gt 0) {
    Add-Result "Tâches planifiées" "Tâches personnelles reconnues (chemin ou signature de confiance)" $SuspTasksTrusted.Count "INFO" ($SuspTasksTrusted.TaskName -join ", ")
}

# ──────────────────────────────────────────────
#  12. SECURE BOOT & TPM
# ──────────────────────────────────────────────
Write-Log "=== 12. SECURE BOOT & TPM ===" -Level SECTION

# Secure Boot
try {
    $SB = Confirm-SecureBootUEFI -ErrorAction Stop
    Add-Result "Sécurité UEFI" "Secure Boot" $(if($SB){"Activé"}else{"DÉSACTIVÉ"}) $(if($SB){"OK"}else{"FAIL"}) $(if(-not $SB){"Secure Boot désactivé — démarrage non sécurisé"})
} catch {
    Add-Result "Sécurité UEFI" "Secure Boot" "Non disponible (BIOS/Legacy ?)" "WARN"
}

# TPM
try {
    $TPM = Get-Tpm -ErrorAction Stop
    Add-Result "Sécurité UEFI" "TPM présent"   $(if($TPM.TpmPresent){"Oui"}else{"Non"})   $(if($TPM.TpmPresent){"OK"}else{"WARN"})
    Add-Result "Sécurité UEFI" "TPM activé"    $(if($TPM.TpmEnabled){"Oui"}else{"Non"})   $(if($TPM.TpmEnabled){"OK"}else{"WARN"})
    Add-Result "Sécurité UEFI" "TPM prêt"      $(if($TPM.TpmReady){"Oui"}else{"Non"})     $(if($TPM.TpmReady){"OK"}else{"WARN"})
} catch {
    Add-Result "Sécurité UEFI" "TPM" "Erreur lecture TPM : $_" "WARN"
}

# ──────────────────────────────────────────────
#  13. POWERSHELL & APPLOCKER
# ──────────────────────────────────────────────
Write-Log "=== 13. POWERSHELL SECURITY ===" -Level SECTION

# NOTE v4.8 : Script Block Logging et Transcription sont des outils de
# surveillance d'entreprise — enregistrement de tous les scripts PS dans les
# journaux d'événements (ID 4104) et fichiers texte pour investigation
# forensique. Sur un poste Windows Home personnel bien géré (Defender actif,
# ASR, HVCI, scripts signés), leur désactivation n'est pas une faiblesse :
# ils génèreraient du bruit inutile sans superviseur pour lire les logs.
# Downgradés de WARN à INFO avec message contextuel.
$PSLogKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$SBL = (Get-ItemProperty $PSLogKey -Name EnableScriptBlockLogging -EA SilentlyContinue).EnableScriptBlockLogging
Add-Result "PowerShell" "Script Block Logging" $(if($SBL -eq 1){"Activé"}else{"Désactivé"}) $(
    if ($SBL -eq 1) { "OK" } else { "INFO" }
) $(if($SBL -eq 1){
    "Enregistrement de tous les scripts PS dans le journal PowerShell Operational (ID 4104)"
} else {
    "Outil de surveillance d'entreprise (journalise tous les scripts PS exécutés) — non obligatoire sur un poste perso bien géré ; utile uniquement si une supervision centralisée lit ces logs"
})

$PSTransKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$PST = (Get-ItemProperty $PSTransKey -Name EnableTranscripting -EA SilentlyContinue).EnableTranscripting
Add-Result "PowerShell" "Transcription PowerShell" $(if($PST -eq 1){"Activée"}else{"Désactivée"}) $(
    if ($PST -eq 1) { "OK" } else { "INFO" }
) $(if($PST -eq 1){
    "Transcription de toutes les sessions PS dans des fichiers texte"
} else {
    "Outil de surveillance d'entreprise (enregistre les sessions PS dans des fichiers texte) — non obligatoire sur un poste perso ; génère des fichiers logs sans valeur sans superviseur pour les analyser"
})

# Politique d'exécution PS
# NOTE v1.1 : le test précédent vérifiait $ep.Policy, qui n'existe pas sur les
# objets renvoyés par Get-ExecutionPolicy -List (la propriété s'appelle
# ExecutionPolicy) — la condition était donc toujours fausse et ne déclenchait
# jamais de FAIL même avec une politique Unrestricted/Bypass active.
$ExecPolicy = Get-ExecutionPolicy -List
foreach ($ep in $ExecPolicy) {
    $st = "INFO"
    if ($ep.ExecutionPolicy -match "Unrestricted|Bypass") { $st = "FAIL" }
    if ($ep.Scope -match "LocalMachine|CurrentUser") {
        Add-Result "PowerShell" "ExecutionPolicy ($($ep.Scope))" $ep.ExecutionPolicy $st $(
            if ($st -eq "FAIL") { "Politique d'exécution trop permissive !" }
        )
    }
}

# NOTE v4.8 : Smart App Control — trois états distincts avec contexte CPU.
# Sur un CPU non-compatible (Kaby Lake i7-7700HQ, antérieur à l'exigence SAC)
# "non disponible" est normal → INFO neutre.
# État 0 = désactivé définitivement (choix délibéré, souvent pour compatibilité
# avec des outils non signés) → INFO contextuel, pas WARN.
# État 1 = actif → OK.
# État 2 = mode évaluation → INFO (Windows décide automatiquement).
$SacKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
$SacRaw = (Get-ItemProperty $SacKey -Name VerifiedAndReputablePolicyState -EA SilentlyContinue).VerifiedAndReputablePolicyState

# Détecter si le CPU est compatible SAC (Tiger Lake+ / Zen 3+ recommandé)
# SAC nécessite Windows 11 22H2+ sur une installation propre — pas activable
# après coup sur un poste mis à niveau depuis Win10.
$SacCpuNote = ""
try {
    $cpuName = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1).Name
    # Heuristique : Intel 7xxx = Kaby Lake (7e gen, non compatible SAC)
    if ($cpuName -match "i\d-7\d{3}|i\d-6\d{3}|i\d-5\d{3}") {
        $SacCpuNote = " (CPU $($cpuName.Trim()) antérieur aux exigences SAC — non disponible sur cette génération)"
    }
} catch {}

if ($null -eq $SacRaw) {
    Add-Result "PowerShell" "Smart App Control" "Non disponible$SacCpuNote" "INFO" "SAC nécessite Windows 11 22H2+ sur une installation propre et un CPU récent — non activable sur un poste mis à niveau ou avec un CPU antérieur à Tiger Lake / Zen 3"
} else {
    $SacLabel = switch ([int]$SacRaw) {
        0 { "Désactivé définitivement$SacCpuNote" }
        1 { "Activé (mode application)" }
        2 { "En mode évaluation (Windows décide automatiquement)" }
        default { "État inconnu ($SacRaw)" }
    }
    $SacStatus = if ([int]$SacRaw -eq 1) { "OK" } else { "INFO" }
    $SacDetail = switch ([int]$SacRaw) {
        0 { "SAC désactivé définitivement — probablement désactivé volontairement pour compatibilité avec des outils non signés (npm, outils portables, etc.). Ne peut plus être réactivé sans réinstaller Windows." }
        1 { "SAC actif — bloque les applications non fiables/non signées au niveau OS. Peut bloquer des outils dev/CLI non signés (npm, cargo, etc.)." }
        2 { "SAC en évaluation — Windows analyse ton usage et décidera automatiquement. Laisser se terminer naturellement (peut prendre quelques semaines)." }
        default { "" }
    }
    Add-Result "PowerShell" "Smart App Control" $SacLabel $SacStatus $SacDetail
}

# NOTE v4.4 : SmartScreen — protection contre les applications et fichiers
# téléchargés depuis Internet non reconnus par Microsoft. Indépendant de SAC.
# Clé : HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SmartScreenEnabled
# Valeurs : "Off" (désactivé), "Warn" (avertissement), "RequireAdmin" (blocage).
$SmartScreenKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
try {
    $SmartScreenVal = (Get-ItemProperty -Path $SmartScreenKey -Name "SmartScreenEnabled" -ErrorAction Stop).SmartScreenEnabled
    $ssLabel = switch ($SmartScreenVal) {
        "Off"          { "Désactivé" }
        "Warn"         { "Activé (avertissement)" }
        "RequireAdmin" { "Activé (blocage administrateur)" }
        default        { "État inconnu ($SmartScreenVal)" }
    }
    $ssStatus = if ($SmartScreenVal -eq "Off") { "WARN" } else { "OK" }
    Add-Result "PowerShell" "Windows SmartScreen" $ssLabel $ssStatus $(
        if ($SmartScreenVal -eq "Off") { "SmartScreen désactivé — les fichiers téléchargés depuis Internet ne sont plus filtrés contre les applications malveillantes connues de Microsoft" } else { "" }
    )
} catch {
    # Clé absente = SmartScreen géré par Windows Defender / Sécurité Windows
    Add-Result "PowerShell" "Windows SmartScreen" "Géré par Windows Defender (clé absente)" "INFO" "SmartScreen est probablement contrôlé via l'application Sécurité Windows plutôt que par cette clé registre"
}

# NOTE v4.4 : Exploit Protection (Process Mitigation Policies).
# Get-ProcessMitigation -System retourne les mitigations système globales.
# On vérifie les deux plus importantes : DEP (Data Execution Prevention —
# empêche l'exécution de code depuis des zones mémoire non-exécutables) et
# ASLR ForceRelocateImages (randomise les adresses mémoire de TOUS les modules
# au démarrage, même ceux non compilés avec /DYNAMICBASE).
try {
    $SysMit = Get-ProcessMitigation -System -ErrorAction Stop

    # NOTE v4.4.1 : Get-ProcessMitigation retourne "NOTSET" quand la mitigation
    # n'est pas configurée explicitement — pas "OFF". NOTSET signifie que Windows
    # applique son comportement par défaut (DEP actif en OptOut, ASLR de base
    # actif) sans forçage explicite. ON = forcé actif, OFF = forcé désactivé,
    # NOTSET = défaut Windows (généralement sûr sur Win11).
    $DepVal  = "$($SysMit.DEP.Enable)"
    $AslrVal = "$($SysMit.ASLR.ForceRelocateImages)"

    $DepStatus  = switch ($DepVal)  { "ON" { "OK" } "OFF" { "WARN" } default { "INFO" } }
    $AslrStatus = switch ($AslrVal) { "ON" { "OK" } "OFF" { "WARN" } default { "INFO" } }

    $DepLabel  = switch ($DepVal)  { "ON" { "Forcé actif" } "OFF" { "Forcé désactivé" } default { "Défaut Windows (NOTSET — actif par défaut sur Win11)" } }
    $AslrLabel = switch ($AslrVal) { "ON" { "Forcé actif" } "OFF" { "Forcé désactivé" } default { "Défaut Windows (NOTSET — actif de base sur Win11)" } }

    Add-Result "PowerShell" "Exploit Protection — DEP système" $DepLabel $DepStatus $(
        if ($DepVal -eq "OFF") { "DEP explicitement désactivé au niveau système — risque d'exécution de code depuis des zones mémoire non prévues à cet effet" } else { "" }
    )
    Add-Result "PowerShell" "Exploit Protection — ASLR ForceRelocate" $AslrLabel $AslrStatus $(
        if ($AslrVal -eq "OFF") { "ASLR ForceRelocateImages explicitement désactivé — les modules non compilés avec /DYNAMICBASE ne sont pas randomisés" } else { "" }
    )
} catch {
    Add-Result "PowerShell" "Exploit Protection" "Lecture impossible" "INFO" "Get-ProcessMitigation non disponible sur cette configuration : $($_.Exception.Message)"
}

# ──────────────────────────────────────────────
#  14. LOGICIELS INSTALLÉS (VULNÉRABLES POTENTIELS)
# ──────────────────────────────────────────────
Write-Log "=== 14. LOGICIELS INSTALLÉS ===" -Level SECTION

$RiskyApps = @("Adobe Reader", "Adobe Acrobat", "Java", "Flash", "VLC", "7-Zip", "WinRAR", "OpenSSH", "PuTTY", "WinSCP", "TeamViewer", "AnyDesk", "UltraVNC")
$Installed = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                              "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

Add-Result "Logiciels" "Total logiciels installés" $Installed.Count "INFO"

# NOTE v1.3 : cette liste signale la PRÉSENCE de logiciels historiquement
# ciblés (souvent via des versions obsolètes) — le script ne consulte aucune
# base de CVE et ne connaît pas la dernière version sortie, donc il ne peut
# pas savoir si l'installation actuelle est vulnérable ou non. Passé en INFO
# (au lieu de WARN) pour éviter de signaler à tort un logiciel à jour comme
# "sensible" ; à toi de vérifier ponctuellement sur le site de l'éditeur.
foreach ($risky in $RiskyApps) {
    $found = $Installed | Where-Object { $_.DisplayName -match $risky }
    if ($found) {
        foreach ($app in $found) {
            Add-Result "Logiciels" "Logiciel à surveiller : $($app.DisplayName)" "v$($app.DisplayVersion)" "INFO" "Présent sur le système — historiquement une cible fréquente si la version est obsolète ; vérifie périodiquement sur le site de l'éditeur que tu as la dernière version"
        }
    }
}

# ──────────────────────────────────────────────
#  15. PROGRAMMES AU DÉMARRAGE (AUTORUNS)
# ──────────────────────────────────────────────
Write-Log "=== 15. PROGRAMMES AU DÉMARRAGE ===" -Level SECTION

function Resolve-ShortcutTarget {
    param([string]$LnkPath)
    try {
        $shell = New-Object -ComObject WScript.Shell
        return $shell.CreateShortcut($LnkPath).TargetPath
    } catch { return $null }
}

$RunKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
$StartupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

$AutorunEntries = [System.Collections.Generic.List[object]]::new()

foreach ($key in $RunKeys) {
    try {
        $props = Get-ItemProperty -Path $key -ErrorAction Stop
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $AutorunEntries.Add([PSCustomObject]@{ Source = $key; Name = $p.Name; Command = "$($p.Value)" })
        }
    } catch {}
}
foreach ($folder in $StartupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
            $cmd = if ($_.Extension -eq ".lnk") { Resolve-ShortcutTarget -LnkPath $_.FullName } else { $_.FullName }
            $AutorunEntries.Add([PSCustomObject]@{ Source = "Dossier Démarrage"; Name = $_.Name; Command = "$cmd" })
        }
    }
}

Add-Result "Démarrage" "Entrées de démarrage automatique" $AutorunEntries.Count "INFO" "Registre Run/RunOnce (HKLM+HKCU) + dossiers Démarrage (raccourcis résolus)"

# NOTE v2.0 : heuristiques volontairement prudentes — un fichier introuvable
# (référence orpheline) ou un lancement depuis un dossier Temp sont des
# signaux nettement plus fiables qu'une simple absence de signature (beaucoup
# de logiciels légitimes, y compris open-source, ne sont pas signés).
foreach ($entry in $AutorunEntries) {
    $exePath = $null
    if ($entry.Command -match '"([^"]+\.(exe|dll))"') { $exePath = $Matches[1] }
    elseif ($entry.Command -match '^([A-Za-z]:\\[^\s"]+\.(exe|dll|cmd|bat|ps1|vbs))') { $exePath = $Matches[1] }
    elseif ($entry.Command -match '\.(exe|dll|cmd|bat|ps1|vbs)$') { $exePath = $entry.Command.Trim() }

    if (-not $exePath) { continue }

    $flagReason = $null
    if (-not (Test-Path -LiteralPath $exePath -ErrorAction SilentlyContinue)) {
        $flagReason = "Référence un fichier introuvable (orphelin) — résidu possible d'une désinstallation, ou indicateur à vérifier"
    } elseif ($exePath -match "\\AppData\\Local\\Temp\\|\\Windows\\Temp\\") {
        $flagReason = "Lancé depuis un dossier temporaire — inhabituel pour un programme légitime au démarrage"
    }

    if ($flagReason) {
        Add-Result "Démarrage" "$($entry.Source) : $($entry.Name)" $entry.Command "WARN" $flagReason
    }
}

# NOTE v4.2 : IFEO (Image File Execution Options) — vecteur de hijacking/
# persistance classique. HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
# Image File Execution Options\ contient une sous-clé par nom d'exécutable.
# Si cette sous-clé a une valeur "Debugger", Windows substitue silencieusement
# ce debugger à l'exe original à chaque lancement — technique utilisée par
# les RAT pour se relancer (ex: remplacer notepad.exe par le malware), ou pour
# créer des portes dérobées sur des exes système (sethc.exe, osk.exe...).
# Une machine saine peut avoir des entrées IFEO légitimes (débogueurs, profilers)
# MAIS elles ne doivent pas pointer vers des chemins inhabituels.
$IFEOKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
try {
    $IFEOEntries = Get-ChildItem -Path $IFEOKey -ErrorAction Stop
    $IFEOSuspect = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $IFEOEntries) {
        $debugger = (Get-ItemProperty -LiteralPath $entry.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
        if ($debugger -and $debugger.Trim() -ne "") {
            $IFEOSuspect.Add("$($entry.PSChildName) → $debugger")
        }
    }
    if ($IFEOSuspect.Count -eq 0) {
        Add-Result "Démarrage" "IFEO — Debugger hijacking" "Aucune entrée Debugger" "OK" "Aucune substitution d'exécutable via Image File Execution Options détectée"
    } else {
        Add-Result "Démarrage" "IFEO — Debugger hijacking" "$($IFEOSuspect.Count) entrée(s) Debugger" "WARN" "Entrées IFEO avec valeur Debugger (vérifier que les chemins sont légitimes) : $($IFEOSuspect -join ' | ')"
    }
} catch {
    Add-Result "Démarrage" "IFEO — Debugger hijacking" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
}

# NOTE v4.2 : AppInit_DLLs — liste de DLL injectées dans TOUS les processus
# Win32 qui chargent User32.dll (soit la quasi-totalité des applications avec
# une interface graphique). Cette fonctionnalité est désactivée par défaut sur
# les systèmes avec Secure Boot actif, mais la valeur registre peut toujours
# être présente. Sur une machine saine, AppInit_DLLs doit être vide ou absente.
# Une DLL dans ce champ est injectée silencieusement dans chaque processus GUI
# sans que l'utilisateur en soit informé — technique utilisée par les rootkits,
# certains logiciels publicitaires, et des outils de hook légitimes (rares).
$AppInitKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
try {
    $AppInitDLLs  = (Get-ItemProperty -Path $AppInitKey -Name "AppInit_DLLs"  -ErrorAction SilentlyContinue).AppInit_DLLs
    $AppInitLoad  = (Get-ItemProperty -Path $AppInitKey -Name "LoadAppInit_DLLs" -ErrorAction SilentlyContinue).LoadAppInit_DLLs
    $AppInit32Key = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    $AppInitDLLs32 = (Get-ItemProperty -Path $AppInit32Key -Name "AppInit_DLLs" -ErrorAction SilentlyContinue).AppInit_DLLs

    $appInitValues = @()
    if ($AppInitDLLs  -and $AppInitDLLs.Trim()   -ne "") { $appInitValues += "64-bit: $AppInitDLLs" }
    if ($AppInitDLLs32 -and $AppInitDLLs32.Trim() -ne "") { $appInitValues += "32-bit: $AppInitDLLs32" }

    if ($appInitValues.Count -eq 0) {
        Add-Result "Démarrage" "AppInit_DLLs (injection DLL globale)" "Vide" "OK" "Aucune DLL d'injection globale configurée"
    } else {
        $loadNote = if ([int]$AppInitLoad -eq 0) { " (LoadAppInit_DLLs=0 — chargement désactivé, mais valeur présente)" } else { " (LoadAppInit_DLLs=1 — ACTIF)" }
        Add-Result "Démarrage" "AppInit_DLLs (injection DLL globale)" "$($appInitValues.Count) DLL configurée(s)$loadNote" "WARN" "DLL détectées : $($appInitValues -join ' | ') — à identifier et valider ; toute DLL inconnue dans AppInit_DLLs est à traiter comme suspecte"
    }
} catch {
    Add-Result "Démarrage" "AppInit_DLLs (injection DLL globale)" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
}

# ──────────────────────────────────────────────
#  16. EXCLUSIONS WINDOWS DEFENDER
# ──────────────────────────────────────────────
Write-Log "=== 16. EXCLUSIONS WINDOWS DEFENDER ===" -Level SECTION

try {
    $Prefs = Get-MpPreference -ErrorAction Stop
    $PathExclusions = @($Prefs.ExclusionPath)
    $ExtExclusions  = @($Prefs.ExclusionExtension)
    $ProcExclusions = @($Prefs.ExclusionProcess)

    Add-Result "Defender" "Exclusions de chemins" $(
        if ($PathExclusions.Count -gt 0) { "$($PathExclusions.Count) : $($PathExclusions -join ', ')" } else { "0" }
    ) "INFO" $(if($PathExclusions.Count -gt 0){"Chemins exclus de l'analyse Defender"})
    Add-Result "Defender" "Exclusions d'extensions" $(
        if ($ExtExclusions.Count -gt 0) { "$($ExtExclusions.Count) : $($ExtExclusions -join ', ')" } else { "0" }
    ) "INFO" $(if($ExtExclusions.Count -gt 0){"Extensions exclues de l'analyse Defender"})
    Add-Result "Defender" "Exclusions de processus" $(
        if ($ProcExclusions.Count -gt 0) { "$($ProcExclusions.Count) : $($ProcExclusions -join ', ')" } else { "0" }
    ) "INFO" $(if($ProcExclusions.Count -gt 0){"Processus exclus de l'analyse Defender"})

    # NOTE v2.0 : ce qui compte vraiment ici, c'est la LARGEUR d'une exclusion
    # (racine de disque, dossier Windows/Users entier, wildcard générique) —
    # ça désactive de fait la protection sur tout son contenu. Une exclusion
    # ciblée comme le fichier hosts est normale et attendue, pas un problème.
    $BroadPatterns = @('^[A-Za-z]:\\?$', '^[A-Za-z]:\\Windows\\?$', '^[A-Za-z]:\\Users\\?$', '^[A-Za-z]:\\Program Files', '\*$')
    foreach ($path in $PathExclusions) {
        $isBroad = $false
        foreach ($pattern in $BroadPatterns) { if ($path -match $pattern) { $isBroad = $true } }
        if ($isBroad) {
            Add-Result "Defender" "Exclusion large détectée" $path "WARN" "Cette exclusion couvre un dossier très large — vérifie qu'elle est volontaire et pas plus large que nécessaire"
        }
    }
} catch {
    Add-Result "Defender" "Exclusions" "Lecture impossible" "WARN" "Erreur : $($_.Exception.Message)"
}

# ──────────────────────────────────────────────
#  17. WINDOWS HELLO / PIN
# ──────────────────────────────────────────────
Write-Log "=== 17. WINDOWS HELLO ===" -Level SECTION

Add-Result "Windows Hello" "PIN/biométrie configuré sur la machine" $(
    if ($HelloConfigured) { "Oui" } elseif ($HelloIndeterminate) { "Indéterminable" } else { "Non détecté" }
) "INFO" $(
    if ($HelloConfigured) {
        "Au moins un identifiant Windows Hello (PIN/biométrie) est enregistré sur ce poste — détection au niveau machine, pas par utilisateur spécifique"
    } elseif ($HelloIndeterminate) {
        "Certains conteneurs d'identifiants sont protégés par des ACL système et restent illisibles même en tant qu'administrateur (seul SYSTEM y a accès) — ce script ne peut donc pas confirmer ou infirmer avec certitude. Vérifie dans Paramètres > Comptes > Options de connexion"
    } else {
        "Aucun identifiant Windows Hello détecté dans les emplacements accessibles sans privilège SYSTEM — si tu te connectes par mot de passe classique uniquement, c'est cohérent ; sinon vérifie dans Paramètres > Comptes > Options de connexion"
    }
)

# ──────────────────────────────────────────────
#  18. SÉCURITÉ BASÉE SUR LA VIRTUALISATION (VBS)
# ──────────────────────────────────────────────
Write-Log "=== 18. VBS / CREDENTIAL GUARD / MEMORY INTEGRITY ===" -Level SECTION

try {
    $DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

    $VBSStatus = switch ([int]$DG.VirtualizationBasedSecurityStatus) {
        0 { "Désactivée" }
        1 { "Activée mais non démarrée" }
        2 { "Activée et en fonctionnement" }
        default { "Inconnu" }
    }
    Add-Result "VBS" "Sécurité basée sur la virtualisation" $VBSStatus $(
        if ([int]$DG.VirtualizationBasedSecurityStatus -eq 2) { "OK" } else { "WARN" }
    ) "Nécessite un CPU compatible (VT-x/AMD-V) + activation au démarrage (Isolation du noyau)"

    $RunningServices = @($DG.SecurityServicesRunning)
    $CredGuardRunning = $RunningServices -contains 1
    $HVCIRunning      = $RunningServices -contains 2

    Add-Result "VBS" "Credential Guard" $(if($CredGuardRunning){"Actif"}else{"Inactif"}) $(
        if ($CredGuardRunning) { "OK" } else { "INFO" }
    ) "Protège les identifiants en mémoire contre le vol (pass-the-hash) — surtout pertinent en environnement de domaine, optionnel sur un poste personnel"

    Add-Result "VBS" "Memory Integrity (HVCI)" $(if($HVCIRunning){"Actif"}else{"Inactif"}) $(
        if ($HVCIRunning) { "OK" } else { "WARN" }
    ) "Empêche le chargement de pilotes non signés/malveillants en mode noyau — activable via Paramètres > Confidentialité et sécurité > Sécurité Windows > Isolation du noyau"
} catch {
    Add-Result "VBS" "Lecture du statut VBS" "Non disponible" "INFO" "Classe WMI absente ou inaccessible sur cette configuration : $($_.Exception.Message)"
}

# NOTE v3.0 : LSA Protection (RunAsPPL) — fait tourner lsass.exe en tant que
# Protected Process Light, empêchant un outil comme Mimikatz d'y lire les
# credentials en mémoire même avec des droits administrateur classiques.
# Complémentaire à Credential Guard ci-dessus (RunAsPPL protège le process
# lui-même, Credential Guard isole les secrets dans un conteneur VBS séparé) ;
# les deux peuvent être actifs indépendamment l'un de l'autre.
$LsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$LsaPplRaw = (Get-ItemProperty $LsaKey -Name RunAsPPL -EA SilentlyContinue).RunAsPPL
if ($null -eq $LsaPplRaw) {
    Add-Result "VBS" "LSA Protection (RunAsPPL)" "Non configuré" "WARN" "lsass.exe tourne sans protection PPL — vulnérable au dump de credentials par des outils type Mimikatz, même avec un compte administrateur local. Activable via 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -> RunAsPPL = 1 (DWORD), puis redémarrage"
} else {
    $LsaPplLabel = switch ([int]$LsaPplRaw) {
        1 { "Activé" }
        2 { "Activé (UEFI lock)" }
        default { "Valeur non standard ($LsaPplRaw)" }
    }
    Add-Result "VBS" "LSA Protection (RunAsPPL)" $LsaPplLabel $(
        if ([int]$LsaPplRaw -ge 1) { "OK" } else { "WARN" }
    ) "Protège lsass.exe contre la lecture de credentials en mémoire par des outils type Mimikatz"
}

# NOTE v4.4 : Kernel-mode Hardware-enforced Stack Protection (KHEStackProtect).
# Protège la pile d'exécution des pilotes noyau contre les attaques de type
# ROP (Return-Oriented Programming) au niveau matériel. Nécessite :
# - CPU Intel Tiger Lake (11e gen+) ou AMD Zen 3+ avec CET (Control-flow
#   Enforcement Technology)
# - HVCI actif (Memory Integrity)
# - Windows 11 22H2+
# La valeur HVCIOptions dans HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config
# est un bitmask : bit 0 = HVCI, bit 3 = KHEStack (valeur 8 ou 9 si les deux).
$CIConfigKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
try {
    $HVCIOptions = (Get-ItemProperty -LiteralPath $CIConfigKey -Name "HVCIOptions" -ErrorAction Stop).HVCIOptions
    $KHEActive = ([int]$HVCIOptions -band 8) -eq 8
    $label = if ($KHEActive) { "Actif (HVCIOptions=0x$("{0:X}" -f [int]$HVCIOptions))" } else { "Inactif (HVCIOptions=0x$("{0:X}" -f [int]$HVCIOptions))" }
    Add-Result "VBS" "Kernel Hardware-enforced Stack Protection" $label $(
        if ($KHEActive) { "OK" } else { "INFO" }
    ) "Protection matérielle de la pile noyau contre les attaques ROP — nécessite CPU Intel 11e gen+/AMD Zen 3+ et HVCI actif"
} catch {
    Add-Result "VBS" "Kernel Hardware-enforced Stack Protection" "Non disponible" "INFO" "Clé CI\Config absente ou inaccessible — probablement non supporté sur ce CPU/configuration : $($_.Exception.Message)"
}

# ──────────────────────────────────────────────
#  19. CERTIFICATS RACINE DE CONFIANCE
# ──────────────────────────────────────────────
Write-Log "=== 19. CERTIFICATS RACINE DE CONFIANCE ===" -Level SECTION

# NOTE v3.1 : la confiance accordée à un certificat ne repose plus QUE sur sa
# présence dans AuthRoot — elle est désormais croisée avec
# $TrustedRootThumbprintAllowlist (empreinte = identité cryptographique non
# falsifiable, voir CONFIGURATION). Le nom (Subject CN) reste affiché en
# toutes lettres pour que tu puisses le reconnaître, mais il ne sert JAMAIS
# de critère pour decider de la légitimité — seule l'empreinte le fait. Une
# fiche complète (nom, émetteur, emplacement, empreinte, statut de
# légitimité, dangerosité estimée) est produite pour chaque certificat hors
# liste Microsoft, vérifié ou non, sans rien masquer.
try {
    $RootCerts = Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction Stop
    $AuthRootCerts = Get-ChildItem -Path "Cert:\LocalMachine\AuthRoot" -ErrorAction SilentlyContinue
    $AuthRootThumbprints = @($AuthRootCerts | Select-Object -ExpandProperty Thumbprint)

    Add-Result "Certificats" "Certificats racine installés" $RootCerts.Count "INFO" "Magasin Cert:\LocalMachine\Root"

    $UnknownRootCerts = $RootCerts | Where-Object {
        $AuthRootThumbprints -notcontains $_.Thumbprint -and $_.Subject -notmatch "Microsoft"
    }

    if ($UnknownRootCerts.Count -eq 0) {
        Add-Result "Certificats" "Certificats racine hors liste Microsoft" "0" "OK" "Tous les certificats racine présents sont alignés avec la liste de confiance Microsoft (CTL AuthRoot) ou émis par Microsoft"
    } else {
        $VerifiedCerts   = $UnknownRootCerts | Where-Object { $TrustedRootThumbprintAllowlist.ContainsKey($_.Thumbprint) }
        $UnverifiedCerts = $UnknownRootCerts | Where-Object { -not $TrustedRootThumbprintAllowlist.ContainsKey($_.Thumbprint) }

        Add-Result "Certificats" "Certificats racine hors liste Microsoft" $UnknownRootCerts.Count $(
            if ($UnverifiedCerts.Count -eq 0) { "OK" } else { "WARN" }
        ) "$($VerifiedCerts.Count) vérifié(s) manuellement (empreinte connue) | $($UnverifiedCerts.Count) non vérifié(s) à examiner. Détail ci-dessous pour chacun"

        foreach ($cert in $UnknownRootCerts) {
            $daysToExpiry = ($cert.NotAfter - (Get-Date)).Days
            $isVerified   = $TrustedRootThumbprintAllowlist.ContainsKey($cert.Thumbprint)

            # Nom lisible (CN) si présent — purement informatif, ne sert
            # jamais à décider de la confiance (un nom est falsifiable).
            $cnMatch    = [regex]::Match($cert.Subject, '^CN=([^,]+)')
            $isGuidLike = $false
            if ($cnMatch.Success) {
                $displayName = $cnMatch.Groups[1].Value
                $isGuidLike  = $displayName -match '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
                $nameNote    = if ($isGuidLike) { "Nom non descriptif (identifiant technique/GUID, pas une raison sociale)" } else { "Nom lisible (CN standard)" }
            } else {
                $displayName = "(aucun CN — identifié par OU/O uniquement)"
                $nameNote    = "Absence de CN — structure de Subject inhabituelle pour une CA commerciale"
            }

            # NOTE v3.4 : détection end-entity vs CA dans le magasin Root.
            # Un magasin "Trusted Root" ne devrait contenir QUE des certificats
            # avec BasicConstraints CA:TRUE (IssuanceTypes include CA). Un
            # certificat "Entité finale" (end-entity, CA:FALSE) placé dans Root
            # est inhabituellement positionné mais beaucoup moins dangereux
            # qu'une vraie CA non reconnue : il ne peut PAS signer d'autres
            # certificats ni intercepter du trafic TLS (MITM impossible).
            # On détecte ce cas via l'extension BasicConstraints (OID 2.5.29.19).
            $isEndEntity = $false
            $bcExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
            if ($bcExt) {
                try {
                    $bcText = $bcExt.Format($false)
                    # "Subject Type=End Entity" ou équivalent localisé français "Entité finale"
                    $isEndEntity = $bcText -match "End Entity|Entité finale|Subject Type=End"
                } catch {}
            }

            # Détection EKU pour enrichir la description
            $ekuLabel = ""
            $ekuExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
            if ($ekuExt) {
                try { $ekuLabel = " | EKU : $($ekuExt.Format($false))" } catch {}
            }

            if ($isVerified) {
                $legitLabel = "Vérifié manuellement — $($TrustedRootThumbprintAllowlist[$cert.Thumbprint])"
                $riskLabel  = if ($isEndEntity) { "Très faible (empreinte confirmée + end-entity : ne peut pas signer d'autres certificats ni faire du MITM)" } else { "Faible (empreinte confirmée)" }
                $certStatus = "OK"
            } else {
                $legitLabel = "Non vérifié — absent à la fois de la CTL Microsoft (AuthRoot) et de l'allowlist locale"
                if ($isEndEntity) {
                    $riskLabel  = "Modéré (end-entity : MITM impossible, mais présence dans Root non standard — identifier l'origine)"
                    $certStatus = "WARN"
                } elseif ($isGuidLike -or -not $cnMatch.Success) {
                    $riskLabel  = "À examiner en priorité (CA possible + nom non descriptif + non vérifié)"
                    $certStatus = "WARN"
                } else {
                    $riskLabel  = "À examiner (CA possible, non vérifié, nom lisible)"
                    $certStatus = "WARN"
                }
            }

            $typeNote   = if ($isEndEntity) { "Entité finale (end-entity) — NE PEUT PAS signer d'autres certificats" } else { "Autorité de certification (CA) — peut signer d'autres certificats" }
            $certDetail = "Nom (CN) : $displayName ($nameNote) | Type : $typeNote | Émetteur : $($cert.Issuer) | Emplacement : Cert:\LocalMachine\Root | Expiration : $($cert.NotAfter.ToString('dd/MM/yyyy')) ($daysToExpiry jours) | Empreinte (SHA-1) : $($cert.Thumbprint)$ekuLabel | Légitimité : $legitLabel | Dangerosité estimée : $riskLabel"

            Add-Result "Certificats" "Certificat racine : $displayName" "$($cert.Subject)" $certStatus $certDetail
        }
    }
} catch {
    Add-Result "Certificats" "Lecture des certificats racine" "Impossible" "INFO" "Erreur : $($_.Exception.Message)"
}

# NOTE v5.0 : certificats expirés dans Cert:\LocalMachine\My.
# Le magasin personnel machine accumule des certificats expirés au fil du temps
# (anciens certificats de signature, certificats d'entreprise révoqués, etc.)
# qui ne sont pas supprimés automatiquement par Windows. Un cert expiré dans My
# ne crée pas de risque de sécurité direct (il ne peut pas être utilisé pour
# signer/chiffrer de nouvelles données), mais il signale une hygiène PKI à
# améliorer et peut provoquer des erreurs d'applications qui le référencent.
# Seuils : expiré depuis >365j = WARN, expiré depuis <365j = INFO.
try {
    $PersonalCerts = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop
    $Now = Get-Date
    $ExpiredCerts = $PersonalCerts | Where-Object { $_.NotAfter -lt $Now }
    $ValidCerts   = $PersonalCerts | Where-Object { $_.NotAfter -ge $Now }

    Add-Result "Certificats" "Magasin personnel machine (Cert:\LocalMachine\My)" "$($PersonalCerts.Count) certificat(s) dont $($ValidCerts.Count) valide(s)" "INFO" "Magasin des certificats personnels de la machine — utilisé pour la signature de code, l'authentification TLS mutuelle, etc."

    if ($ExpiredCerts.Count -eq 0) {
        Add-Result "Certificats" "Certificats expirés (Cert:\LocalMachine\My)" "0" "OK" "Aucun certificat expiré dans le magasin personnel machine"
    } else {
        $OldExpired = $ExpiredCerts | Where-Object { ($Now - $_.NotAfter).TotalDays -gt 365 }
        $RecentExp  = $ExpiredCerts | Where-Object { ($Now - $_.NotAfter).TotalDays -le 365 }
        $expStatus  = if ($OldExpired.Count -gt 0) { "WARN" } else { "INFO" }
        $expDetails = $ExpiredCerts | Select-Object -First 10 | ForEach-Object {
            $daysSince = [int]($Now - $_.NotAfter).TotalDays
            $cn = if ($_.Subject -match 'CN=([^,]+)') { $Matches[1] } else { $_.Subject }
            "$cn (expiré il y a $daysSince j — $($_.Thumbprint.Substring(0,12))…)"
        }
        $moreNote = if ($ExpiredCerts.Count -gt 10) { " (+$($ExpiredCerts.Count - 10) autres)" } else { "" }
        Add-Result "Certificats" "Certificats expirés (Cert:\LocalMachine\My)" "$($ExpiredCerts.Count) certificat(s) expiré(s)$moreNote" $expStatus "$(if($OldExpired.Count -gt 0){"$($OldExpired.Count) expiré(s) depuis plus d'1 an — nettoyage recommandé. "})Détails : $($expDetails -join ' | '). Pour nettoyer : Get-ChildItem Cert:\LocalMachine\My | Where-Object {`$_.NotAfter -lt (Get-Date)} | Remove-Item"
    }
} catch {
    Add-Result "Certificats" "Certificats expirés (Cert:\LocalMachine\My)" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
}

# ──────────────────────────────────────────────
#  20. PROTOCOLES TLS/SSL ET CIPHER SUITES (SCHANNEL)
# ──────────────────────────────────────────────
Write-Log "=== 20. TLS/SSL & CIPHER SUITES ===" -Level SECTION

# NOTE v4.0 : SCHANNEL pilote les protocoles SSL/TLS au niveau système Windows
# (IIS, WinHTTP, RDP, LDAPS, etc.). Les clés sous Protocols\ sont organisées
# en sous-dossiers nommés par protocole, avec un sous-dossier Client et Server
# chacun, et une valeur DWORD "Enabled" (1 = forcé actif, 0 = forcé inactif).
# ATTENTION : une clé ABSENTE ne veut pas dire "désactivé" — Windows applique
# ses propres valeurs par défaut, qui varient selon la build. On distingue donc
# explicitement "forcé désactivé par clé registre" / "forcé activé" /
# "non configuré (défaut Windows)".

$SchannelBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

$TlsProtos = @(
    @{ Name="SSL 2.0";  WarnIfEnabled=$true;  WarnIfAbsent=$false; ShouldBeDisabled=$true  },
    @{ Name="SSL 3.0";  WarnIfEnabled=$true;  WarnIfAbsent=$false; ShouldBeDisabled=$true  },
    @{ Name="TLS 1.0";  WarnIfEnabled=$true;  WarnIfAbsent=$true;  ShouldBeDisabled=$true  },
    @{ Name="TLS 1.1";  WarnIfEnabled=$true;  WarnIfAbsent=$true;  ShouldBeDisabled=$true  },
    @{ Name="TLS 1.2";  WarnIfEnabled=$false; WarnIfAbsent=$false; ShouldBeDisabled=$false },
    @{ Name="TLS 1.3";  WarnIfEnabled=$false; WarnIfAbsent=$false; ShouldBeDisabled=$false }
)

foreach ($proto in $TlsProtos) {
    foreach ($role in @("Client","Server")) {
        $keyPath = "$SchannelBase\$($proto.Name)\$role"
        try {
            $keyExists = Test-Path -LiteralPath $keyPath -ErrorAction Stop
            if ($keyExists) {
                $enabledVal = (Get-ItemProperty -LiteralPath $keyPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                if ($null -eq $enabledVal) {
                    $label  = "Non configuré (défaut Windows — clé présente, valeur Enabled absente)"
                    $status = "INFO"
                } elseif ([int]$enabledVal -eq 0) {
                    $label  = "Forcé DÉSACTIVÉ (registre)"
                    $status = if ($proto.ShouldBeDisabled) { "OK" } else { "WARN" }
                    $detail = if (-not $proto.ShouldBeDisabled) { "$($proto.Name) est forcé désactivé côté $role — ce protocole devrait rester actif (risque de blocage des connexions)" } else { "" }
                } else {
                    $label  = "Forcé ACTIVÉ (registre, valeur $enabledVal)"
                    $status = if ($proto.ShouldBeDisabled) { "FAIL" } else { "OK" }
                    $detail = if ($proto.ShouldBeDisabled) { "$($proto.Name) est explicitement activé côté $role — protocole déprécié/vulnérable, doit être désactivé (POODLE, BEAST…)" } else { "" }
                }
            } else {
                $label = "Non configuré (défaut Windows — clé absente)"
                if ($proto.ShouldBeDisabled -and $proto.WarnIfAbsent) {
                    $status = "WARN"
                    $detail = "$($proto.Name) n'est pas explicitement désactivé via le registre — Windows peut l'activer par défaut sur certaines builds/configurations. Recommandé : forcer Enabled=0 pour garantir la désactivation."
                } elseif (-not $proto.ShouldBeDisabled -and $proto.WarnIfAbsent) {
                    $status = "WARN"
                    $detail = "$($proto.Name) n'est pas explicitement activé via le registre — Windows devrait l'activer par défaut sur Win11, mais sans clé de forçage ce n'est pas garanti sur toutes les configurations."
                } else {
                    $status = "INFO"
                    $detail = ""
                }
            }
            Add-Result "TLS/SCHANNEL" "$($proto.Name) ($role)" $label $status $detail
        } catch {
            Add-Result "TLS/SCHANNEL" "$($proto.Name) ($role)" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
        }
    }
}

$CipherPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$WeakCipherPatterns = @("RC4","3DES","DES","NULL","EXPORT","ANON")

try {
    if (Test-Path -LiteralPath $CipherPolicyKey -ErrorAction Stop) {
        $cipherList = (Get-ItemProperty -LiteralPath $CipherPolicyKey -Name "Functions" -ErrorAction SilentlyContinue).Functions
        if ($cipherList) {
            $suites      = $cipherList -split ","
            $weakFound   = [System.Collections.Generic.List[string]]::new()
            foreach ($suite in $suites) {
                $s = $suite.Trim()
                foreach ($pattern in $WeakCipherPatterns) {
                    if ($s -match $pattern) { $weakFound.Add($s); break }
                }
            }
            if ($weakFound.Count -gt 0) {
                Add-Result "TLS/SCHANNEL" "Cipher suites faibles (GPO/registre)" "$($weakFound.Count) suite(s) faible(s) détectée(s)" "FAIL" "Suites à risque dans la liste forcée : $($weakFound -join ', ') — RC4/NULL/EXPORT doivent être retirés immédiatement"
            } else {
                Add-Result "TLS/SCHANNEL" "Cipher suites (GPO/registre)" "$($suites.Count) suite(s) configurée(s)" "OK" "Aucune suite faible détectée dans la liste forcée par GPO/registre"
            }
        } else {
            Add-Result "TLS/SCHANNEL" "Cipher suites (GPO/registre)" "Clé présente, valeur Functions absente" "INFO" "La clé de politique existe mais ne contient pas de liste de suites — Windows gère les suites par défaut"
        }
    } else {
        Add-Result "TLS/SCHANNEL" "Cipher suites (GPO/registre)" "Non configuré (défaut Windows)" "INFO" "Aucune liste de cipher suites forcée via GPO ou registre — Windows 11 gère les suites de chiffrement par défaut (TLS_AES_256_GCM_SHA384, ECDHE_AES_256, etc. — généralement sécurisées)"
    }
} catch {
    Add-Result "TLS/SCHANNEL" "Cipher suites (GPO/registre)" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
}

# ──────────────────────────────────────────────
#  21. PILOTES VULNÉRABLES (HVCI BLOCKLIST + DRIVERS RÉCENTS)
# ──────────────────────────────────────────────
Write-Log "=== 21. PILOTES VULNÉRABLES ===" -Level SECTION

# NOTE v4.4 : deux contrôles complémentaires sur la surface d'attaque pilotes.
#
# 1. Microsoft Vulnerable Driver Blocklist (HVCI Blocklist)
$VDBLKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
try {
    $VDBLVal = (Get-ItemProperty -LiteralPath $VDBLKey -Name "VulnerableDriverBlocklistEnable" -ErrorAction Stop).VulnerableDriverBlocklistEnable
    if ([int]$VDBLVal -eq 1) {
        Add-Result "Démarrage" "HVCI Vulnerable Driver Blocklist" "Activée (forcée par registre)" "OK" "La blocklist Microsoft des drivers vulnérables connus est forcée via registre — protection BYOVD active indépendamment de HVCI"
    } else {
        Add-Result "Démarrage" "HVCI Vulnerable Driver Blocklist" "Désactivée (valeur=$VDBLVal)" "WARN" "La blocklist est explicitement désactivée — les drivers vulnérables connus (BYOVD) ne sont pas bloqués au chargement"
    }
} catch {
    Add-Result "Démarrage" "HVCI Vulnerable Driver Blocklist" "Non forcée (défaut HVCI)" "INFO" "Clé VulnerableDriverBlocklistEnable absente — la blocklist est active si Memory Integrity (HVCI) est activé, sinon non appliquée"
}

# 2. Drivers récemment installés (événement System 7045, 24h)
try {
    $RecentDrivers = Get-WinEvent -FilterHashtable @{
        LogName   = "System"
        Id        = 7045
        StartTime = (Get-Date).AddHours(-24)
    } -MaxEvents 50 -ErrorAction SilentlyContinue

    $driverCount = if ($null -eq $RecentDrivers) { 0 } else { @($RecentDrivers).Count }

    if ($driverCount -eq 0) {
        Add-Result "Démarrage" "Pilotes installés récemment (24h)" "0" "OK" "Aucun nouveau service/pilote noyau installé dans les dernières 24h"
    } else {
        $suspDrivers = [System.Collections.Generic.List[string]]::new()
        $okDrivers   = [System.Collections.Generic.List[string]]::new()

        foreach ($ev in @($RecentDrivers)) {
            try {
                $svcName  = $ev.Properties[0].Value
                $svcPath  = "$($ev.Properties[1].Value)"
                $isKernel = $ev.Properties[2].Value -match "kernel"
                $isSuspect = $svcPath -notmatch "(?i)system32\\drivers|driverstore\\filerepository|windows\\inf|program files\\wsl|program files\\windowsapps" -and
                             $svcPath -ne "0"
                if ($isSuspect) {
                    $suspDrivers.Add("$svcName : $svcPath$(if($isKernel){' [kernel]'})")
                } else {
                    $okDrivers.Add($svcName)
                }
            } catch {}
        }

        $status = if ($suspDrivers.Count -gt 0) { "WARN" } else { "INFO" }
        $detail = if ($suspDrivers.Count -gt 0) {
            "Drivers hors circuit Windows normal : $($suspDrivers -join ' | ')"
        } else {
            "Tous les drivers sont dans des chemins standard Windows : $($okDrivers -join ', ')"
        }
        Add-Result "Démarrage" "Pilotes installés récemment (24h)" "$driverCount service(s)/pilote(s)" $status $detail
    }
} catch {
    Add-Result "Démarrage" "Pilotes installés récemment (24h)" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
}

# ──────────────────────────────────────────────
#  22. SHADOW COPY / VSS (RÉSISTANCE RANSOMWARE)
# ──────────────────────────────────────────────
Write-Log "=== 22. SHADOW COPY / VSS ===" -Level SECTION

# NOTE v5.0 : les ransomwares suppriment systématiquement les shadow copies
# (vssadmin delete shadows /all /quiet ou wmic shadowcopy delete) avant de
# chiffrer les fichiers, pour empêcher toute récupération. La présence de
# clichés instantanés récents sur C: est donc un indicateur de résistance :
# un ransomware qui a échoué à les supprimer (protection VSS active, tamper
# protection Defender, etc.) laissera un point de restauration exploitable.
#
# Deux vérifications complémentaires :
# 1. Statut du service VSS — arrêté en mode Manuel est normal (VSS est lancé
#    à la demande par Windows), mais Disabled est une anomalie.
# 2. Existence de shadow copies récentes via vssadmin list shadows.
#    On parse la sortie texte (disponible sur toutes les éditions Win11
#    y compris Home, contrairement aux cmdlets WMI VSS qui nécessitent
#    parfois le service en état Running pour être interrogées).

# 1. Statut du service VSS
try {
    $VssSvc = Get-Service -Name VSS -ErrorAction Stop
    if ($VssSvc.StartType -eq "Disabled") {
        Add-Result "Sauvegarde" "Service VSS (Volume Shadow Copy)" "DÉSACTIVÉ ($($VssSvc.StartType))" "FAIL" "Le service VSS est désactivé — aucun cliché instantané ne peut être créé. Les sauvegardes Windows, les points de restauration et la résistance ransomware via VSS sont tous inactifs. Réactiver : Set-Service VSS -StartupType Manual"
    } else {
        Add-Result "Sauvegarde" "Service VSS (Volume Shadow Copy)" "$($VssSvc.Status) (démarrage : $($VssSvc.StartType))" "OK" "Le service VSS est en démarrage Manuel (normal — lancé à la demande pour les opérations de sauvegarde/snapshot)"
    }
} catch {
    Add-Result "Sauvegarde" "Service VSS (Volume Shadow Copy)" "Lecture impossible" "WARN" "Erreur : $($_.Exception.Message)"
}

# 2. Shadow copies existantes via vssadmin list shadows
try {
    # NOTE v5.0 : vssadmin peut produire une sortie UTF-16LE sur certaines
    # configurations — on utilise le même pattern que la section SFC/DISM de
    # Check-Boot_Win11 (suppression des NULs via -replace "`0","").
    $vssOutput = & vssadmin list shadows /for=$env:SystemDrive 2>&1
    $vssText = ($vssOutput -join "`n") -replace "`0",""

    # NOTE v5.0.1 : deux niveaux de détection distincts, dans l'ordre :
    # 1. vssadmin signale explicitement l'absence de clichés → FAIL direct.
    # 2. On compte les blocs "ID de cliché" AVANT de tenter le parsing des dates.
    #    Si 0 blocs → FAIL (aucune shadow copy malgré une sortie non vide, ex:
    #    message d'en-tête seul sans bloc). Si N blocs > 0 → on tente le parsing
    #    des dates pour affiner (OK/WARN selon l'âge). Si parsing échoue malgré
    #    des blocs présents → INFO avec count exact (shadow copies présentes mais
    #    format de date non parsable sur cette locale/build).
    #
    # NOTE v5.0.3 : sur Windows 11 Home, vssadmin list shadows /for=C: retourne
    # systématiquement 0 résultat car les shadow copies VSS génériques ne sont pas
    # créées automatiquement. Seuls les POINTS DE RESTAURATION SYSTÈME existent,
    # qui sont techniquement des shadow copies VSS mais cataloguées différemment
    # (elles n'apparaissent pas avec /for=C: mais sont bien protégées par VSS).
    # On interroge Get-ComputerRestorePoint en complément — s'il retourne des
    # points de restauration récents, c'est une protection ransomware valable
    # et on affiche OK/WARN selon l'âge, sans FAIL injustifié.
    $isExplicitlyEmpty = $vssText -match "Aucun.+trouv|No items found|Il n.existe aucun|There are no|no shadow copies"

    # Compter les blocs indépendamment du format de date (robuste à la locale)
    $shadowBlockCount = ([regex]::Matches($vssText, "ID de clich|Shadow Copy ID|Snapshot ID")).Count

    # Points de restauration système (Win11 Home — complément à vssadmin)
    $RestorePoints = $null
    try {
        $RestorePoints = Get-ComputerRestorePoint -ErrorAction Stop |
            Sort-Object -Property CreationTime -Descending
    } catch {}

    if ($shadowBlockCount -gt 0) {
        # Shadow copies VSS génériques présentes — parsing des dates
        $shadowDates = [regex]::Matches($vssText, 'Date et heure de cr[ée]ation\s*:\s*(.+)|Creation Time\s*:\s*(.+)|Date de cr[ée]ation\s*:\s*(.+)') |
            ForEach-Object {
                $dateStr = ($_.Groups[1].Value + $_.Groups[2].Value + $_.Groups[3].Value).Trim()
                if ($dateStr -ne "") { try { [datetime]::Parse($dateStr) } catch { $null } }
            } | Where-Object { $_ -ne $null } | Sort-Object -Descending

        if ($shadowDates.Count -gt 0) {
            $mostRecent = $shadowDates[0]
            $ageInDays  = [int]((Get-Date) - $mostRecent).TotalDays
            if ($ageInDays -le 7) {
                Add-Result "Sauvegarde" "Clichés instantanés (Shadow Copies) sur $env:SystemDrive" "$shadowBlockCount cliché(s) — dernier il y a $ageInDays jour(s)" "OK" "Shadow copies VSS présentes et récentes — bonne résistance ransomware. Dernier cliché : $($mostRecent.ToString('dd/MM/yyyy HH:mm'))"
            } elseif ($ageInDays -le 30) {
                Add-Result "Sauvegarde" "Clichés instantanés (Shadow Copies) sur $env:SystemDrive" "$shadowBlockCount cliché(s) — dernier il y a $ageInDays jour(s)" "WARN" "Shadow copies VSS présentes mais le plus récent date de $ageInDays jours. Dernier : $($mostRecent.ToString('dd/MM/yyyy HH:mm'))"
            } else {
                Add-Result "Sauvegarde" "Clichés instantanés (Shadow Copies) sur $env:SystemDrive" "$shadowBlockCount cliché(s) — dernier il y a $ageInDays jour(s)" "WARN" "Shadow copies VSS très anciennes ($ageInDays jours) — envisager un nouveau point de restauration : Checkpoint-Computer -Description 'Manuel' -RestorePointType MODIFY_SETTINGS"
            }
        } else {
            Add-Result "Sauvegarde" "Clichés instantanés (Shadow Copies) sur $env:SystemDrive" "$shadowBlockCount cliché(s) détecté(s)" "INFO" "$shadowBlockCount bloc(s) détecté(s) — shadow copies présentes mais date non parsable. Vérifier : vssadmin list shadows /for=$env:SystemDrive"
        }
    } elseif ($RestorePoints -and $RestorePoints.Count -gt 0) {
        # Pas de shadow copies VSS génériques mais des points de restauration système
        # → protection ransomware valable sur Win11 Home
        $lastRP  = $RestorePoints[0]
        $rpDate  = [Management.ManagementDateTimeConverter]::ToDateTime($lastRP.CreationTime)
        $rpAge   = [int]((Get-Date) - $rpDate).TotalDays
        $rpNames = ($RestorePoints | Select-Object -First 3 | ForEach-Object {
            $dt = [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime)
            "$($_.Description) ($($dt.ToString('dd/MM/yyyy')))"
        }) -join " | "

        if ($rpAge -le 30) {
            Add-Result "Sauvegarde" "Clichés instantanés (Shadow Copies) sur $env:SystemDrive" "0 VSS générique — $($RestorePoints.Count) point(s) de restauration" "OK" "Aucune shadow copy VSS générique (normal sur Win11 Home) mais $($RestorePoints.Count) point(s) de restauration système présents — protection ransomware valable. Dernier : il y a $rpAge jour(s). Points : $rpNames"
        } else {
            Add-Result "Sauvegarde" "Clichés instantanés (Shadow Copies) sur $env:SystemDrive" "0 VSS générique — $($RestorePoints.Count) point(s) de restauration (dernier : $rpAge j)" "WARN" "Points de restauration présents mais anciens ($rpAge jours). Points : $rpNames. Créer un nouveau : Checkpoint-Computer -Description 'Manuel' -RestorePointType MODIFY_SETTINGS"
        }
    } else {
        # Vraiment aucune protection VSS — ni shadow copy ni point de restauration
        Add-Result "Sauvegarde" "Clichés instantanés (Shadow Copies) sur $env:SystemDrive" "0" "FAIL" "Aucun cliché instantané ni point de restauration sur $env:SystemDrive — en cas de ransomware, aucune récupération VSS possible. Activer la protection système sur C: puis : Checkpoint-Computer -Description 'Manuel' -RestorePointType MODIFY_SETTINGS, ou via Paramètres > Système > À propos > Protection du système"
    }
} catch {
    Add-Result "Sauvegarde" "Clichés instantanés (Shadow Copies)" "Lecture impossible" "WARN" "Erreur lors de l'appel à vssadmin : $($_.Exception.Message)"
}

# NOTE v5.0.4 : sauvegarde image système via wbadmin (Sauvegarde Windows /
# "Windows 7 Backup"). wbadmin get versions liste les versions de sauvegarde
# complètes disponibles sur tous les volumes connectés. On parse la sortie
# texte pour extraire les dates et le volume cible.
# Seuils : >30j WARN, >90j FAIL, 0 version → INFO (pas de sauvegarde wbadmin
# configurée — pas forcément un problème si une autre solution est en place).
try {
    $wbOutput = & wbadmin get versions 2>&1
    $wbText   = ($wbOutput -join "`n") -replace "`0",""

    $isNoBackup = $wbText -match "Aucune sauvegarde|No backup|n.a pas pu|could not"

    # Extraire les dates de sauvegarde
    # NOTE v5.0.5 : le champ réel sur locale FR est "Durée de sauvegarde : dd/MM/yyyy HH:mm"
    # (et non "Heure de la sauvegarde" comme supposé en v5.0.4 — corrigé après
    # analyse de la sortie réelle sur NEPH-DESKTOP). Format date : dd/MM/yyyy HH:mm,
    # parsé avec [datetime]::ParseExact pour éviter les ambiguïtés MM/dd vs dd/MM.
    $wbDates = [regex]::Matches($wbText, "Dur[eé]e de sauvegarde\s*:\s*(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2})|Backup time\s*:\s*(.+)") |
        ForEach-Object {
            $dateStr = ($_.Groups[1].Value + $_.Groups[2].Value).Trim()
            if ($dateStr -ne "") {
                try {
                    [datetime]::ParseExact($dateStr, "dd/MM/yyyy HH:mm",
                        [System.Globalization.CultureInfo]::InvariantCulture)
                } catch {
                    try { [datetime]::Parse($dateStr) } catch { $null }
                }
            }
        } | Where-Object { $_ -ne $null } | Sort-Object -Descending

    # Extraire le volume cible (ex: "Disque dur étiqueté Auto_Save_Windows(E:)")
    $wbTargets = [regex]::Matches($wbText, "Cible de sauvegarde\s*:\s*(.+)|Backup target\s*:\s*(.+)") |
        ForEach-Object { ($_.Groups[1].Value + $_.Groups[2].Value).Trim() } |
        Where-Object { $_ -ne "" } | Select-Object -Unique

    $wbTargetStr = if ($wbTargets.Count -gt 0) { $wbTargets -join ", " } else { "volume non identifié" }

    if ($isNoBackup -or $wbDates.Count -eq 0) {
        Add-Result "Sauvegarde" "Sauvegarde image système (wbadmin)" "Aucune version trouvée" "INFO" "Aucune sauvegarde image système wbadmin détectée sur les volumes connectés — si une autre solution de sauvegarde est en place (Macrium, Veeam, etc.), ce résultat est normal"
    } else {
        $lastBackup = $wbDates[0]
        $ageInDays  = [int]((Get-Date) - $lastBackup).TotalDays
        $countStr   = "$($wbDates.Count) version(s)"
        $lastStr    = $lastBackup.ToString('dd/MM/yyyy HH:mm')

        if ($ageInDays -le 30) {
            Add-Result "Sauvegarde" "Sauvegarde image système (wbadmin)" "$countStr — dernière il y a $ageInDays jour(s)" "OK" "Sauvegarde image système récente sur $wbTargetStr. Dernière : $lastStr — restauration complète du système possible"
        } elseif ($ageInDays -le 90) {
            Add-Result "Sauvegarde" "Sauvegarde image système (wbadmin)" "$countStr — dernière il y a $ageInDays jour(s)" "WARN" "Dernière sauvegarde image il y a $ageInDays jours ($lastStr) sur $wbTargetStr — relancer une sauvegarde manuelle : Panneau de configuration → Sauvegarder et restaurer (Windows 7)"
        } else {
            Add-Result "Sauvegarde" "Sauvegarde image système (wbadmin)" "$countStr — dernière il y a $ageInDays jour(s)" "FAIL" "Dernière sauvegarde image il y a $ageInDays jours ($lastStr) sur $wbTargetStr — sauvegarde très ancienne, relancer immédiatement"
        }
    }
} catch {
    Add-Result "Sauvegarde" "Sauvegarde image système (wbadmin)" "Lecture impossible" "INFO" "Erreur lors de l'appel à wbadmin : $($_.Exception.Message)"
}

# NOTE v5.0.6 : planification de la sauvegarde Windows (Win11 Home).
# wbadmin get schedule n'est pas disponible sur Windows Home (commande
# réservée à Windows Server). Sur Home, la planification est gérée par
# la tâche planifiée \Microsoft\Windows\WindowsBackup\AutomaticBackup.
# On interroge cette tâche via Get-ScheduledTask pour déterminer si une
# planification automatique est active.
# Statuts possibles :
#   Ready    = tâche active et en attente de sa prochaine exécution → OK
#   Running  = sauvegarde en cours → OK
#   Disabled = planification désactivée → WARN
#   Absent   = tâche supprimée ou jamais configurée → INFO
try {
    $WbTask = Get-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsBackup\" `
                                -TaskName "AutomaticBackup" `
                                -ErrorAction Stop

    $taskState  = $WbTask.State.ToString()
    $taskInfo   = Get-ScheduledTaskInfo -TaskPath "\Microsoft\Windows\WindowsBackup\" `
                                         -TaskName "AutomaticBackup" `
                                         -ErrorAction SilentlyContinue

    # Extraire le déclencheur (fréquence planifiée)
    $triggerDesc = if ($WbTask.Triggers.Count -gt 0) {
        $t = $WbTask.Triggers[0]
        $freq = switch ($t.CimClass.CimClassName) {
            "MSFT_TaskDailyTrigger"   { "Quotidienne" }
            "MSFT_TaskWeeklyTrigger"  { "Hebdomadaire" }
            "MSFT_TaskTimeTrigger"    { "Ponctuelle" }
            default                   { $t.CimClass.CimClassName -replace "MSFT_Task|Trigger","" }
        }
        $startTime = if ($t.StartBoundary) {
            try { ([datetime]$t.StartBoundary).ToString("HH:mm") } catch { "?" }
        } else { "?" }
        "$freq à $startTime"
    } else { "Aucun déclencheur configuré" }

    $nextRun = if ($taskInfo -and $taskInfo.NextRunTime -and
                   $taskInfo.NextRunTime -gt [datetime]"2000-01-01") {
        $taskInfo.NextRunTime.ToString("dd/MM/yyyy HH:mm")
    } else { "Non planifiée" }

    $lastRun = if ($taskInfo -and $taskInfo.LastRunTime -and
                   $taskInfo.LastRunTime -gt [datetime]"2000-01-01") {
        $taskInfo.LastRunTime.ToString("dd/MM/yyyy HH:mm")
    } else { "Jamais" }

    switch ($taskState) {
        "Ready" {
            Add-Result "Sauvegarde" "Planification sauvegarde automatique (wbadmin)" "$triggerDesc — prochaine : $nextRun" "OK" "La tâche AutomaticBackup est active. Fréquence : $triggerDesc. Prochaine exécution : $nextRun. Dernière exécution : $lastRun"
        }
        "Running" {
            Add-Result "Sauvegarde" "Planification sauvegarde automatique (wbadmin)" "Sauvegarde en cours" "OK" "Une sauvegarde automatique est actuellement en cours d'exécution"
        }
        "Disabled" {
            Add-Result "Sauvegarde" "Planification sauvegarde automatique (wbadmin)" "Désactivée" "WARN" "La tâche AutomaticBackup est désactivée — les sauvegardes ne s'exécutent plus automatiquement. Réactiver via : Panneau de configuration → Sauvegarder et restaurer (Windows 7) → Modifier les paramètres"
        }
        default {
            Add-Result "Sauvegarde" "Planification sauvegarde automatique (wbadmin)" $taskState "INFO" "État de la tâche AutomaticBackup : $taskState"
        }
    }
} catch {
    # Tâche absente = sauvegarde jamais configurée ou supprimée
    if ($_.Exception.Message -match "No MSFT_ScheduledTask|introuvable|not found|cannot find") {
        Add-Result "Sauvegarde" "Planification sauvegarde automatique (wbadmin)" "Tâche absente" "INFO" "La tâche AutomaticBackup n'existe pas — aucune sauvegarde automatique planifiée. Si tu utilises la sauvegarde manuelle uniquement, ce résultat est normal. Pour configurer : Panneau de configuration → Sauvegarder et restaurer (Windows 7) → Configurer la sauvegarde"
    } else {
        Add-Result "Sauvegarde" "Planification sauvegarde automatique (wbadmin)" "Lecture impossible" "INFO" "Erreur : $($_.Exception.Message)"
    }
}

# ──────────────────────────────────────────────
#  RÉSUMÉ
# ──────────────────────────────────────────────
$TotalOK   = ($AuditResults | Where-Object { $_.Statut -eq "OK"   }).Count
$TotalWARN = ($AuditResults | Where-Object { $_.Statut -eq "WARN" }).Count
$TotalFAIL = ($AuditResults | Where-Object { $_.Statut -eq "FAIL" }).Count
$TotalINFO = ($AuditResults | Where-Object { $_.Statut -eq "INFO" }).Count
$Total     = $AuditResults.Count

# NOTE v4.1 : refonte du scoring — passage d'un modèle "malus linéaire"
# à un modèle "% de réussite pondéré par catégorie".
#
# PROBLÈME de l'ancien modèle (v3.x/v4.0) :
#   Score = 100 − somme(malus par résultat FAIL/WARN)
#   Avec 3 FAIL BitLocker (poids 1.6) → 3 × 10 × 1.6 = 48 pts de malus
#   seuls, avant même les WARN. Ajouter une nouvelle section TLS avec 6 WARN
#   → 25 pts de plus → score = 1/100 malgré une machine globalement bien
#   sécurisée (HVCI actif, LSA PPL, ASR, Secure Boot…). Le modèle linéaire
#   est incontrôlable : chaque nouveau contrôle creuse le score même si la
#   machine est saine, parce qu'il ignore le nombre total de contrôles.
#
# NOUVEAU MODÈLE :
#   Pour chaque catégorie C :
#     - On compte les contrôles OK/INFO (réussis) et WARN/FAIL (en défaut)
#     - On pondère FAIL à 0.0 et WARN à 0.5 (demi-réussite), OK/INFO à 1.0
#     - taux_C = somme(valeur_statut) / nb_contrôles_C
#   Score final = Σ(poids_C × taux_C) / Σ(poids_C) × 100
#
#   Propriétés :
#   - Invariant au nombre de contrôles par catégorie (1 ou 20, ça ne fait
#     pas dériver le score).
#   - Un FAIL BitLocker impacte la catégorie BitLocker (→ 0%), pas les autres.
#   - Une catégorie à 0% (tous FAIL) retire exactement poids_C / Σpoids_C du score.
#   - Un poste avec tout en OK = 100. Un poste avec tout en FAIL = 0.
#   - Les catégories sans poids défini reçoivent 1.0.

$CatStats = @{}
foreach ($result in $AuditResults) {
    $cat = $result.Categorie
    if (-not $CatStats.ContainsKey($cat)) {
        $CatStats[$cat] = @{ WeightedSum = 0.0; Count = 0 }
    }
    $val = switch ($result.Statut) {
        "OK"   { 1.0 }
        "INFO" { 1.0 }
        "WARN" { 0.5 }
        "FAIL" { 0.0 }
        default { 1.0 }
    }
    $CatStats[$cat].WeightedSum += $val
    $CatStats[$cat].Count++
}

$ScoreNumerator   = 0.0
$ScoreDenominator = 0.0
foreach ($cat in $CatStats.Keys) {
    $weight   = if ($CategoryWeights.ContainsKey($cat)) { $CategoryWeights[$cat] } else { 1.0 }
    $catRate  = $CatStats[$cat].WeightedSum / $CatStats[$cat].Count
    $ScoreNumerator   += $weight * $catRate
    $ScoreDenominator += $weight
}
$Score = if ($ScoreDenominator -gt 0) {
    [int][math]::Round(100 * $ScoreNumerator / $ScoreDenominator)
} else { 100 }
$ScoreColor = if ($Score -ge 80) { "#27ae60" } elseif ($Score -ge 50) { "#f39c12" } else { "#e74c3c" }

Write-Log "=== RÉSUMÉ ===" -Level SECTION
Write-Log "Total contrôles : $Total | OK: $TotalOK | WARN: $TotalWARN | FAIL: $TotalFAIL | INFO: $TotalINFO" -Level INFO
Write-Log "Score de sécurité estimé (pondéré par catégorie) : $Score / 100" -Level $(if($Score -ge 80){"OK"}elseif($Score -ge 50){"WARN"}else{"FAIL"})

# ──────────────────────────────────────────────
#  ÉVOLUTION DEPUIS LE DERNIER AUDIT (DELTAS)
# ──────────────────────────────────────────────
$Deltas = [System.Collections.Generic.List[object]]::new()

if ($PreviousAudit -and $PreviousAudit.Results) {
    $PrevMap = @{}
    foreach ($p in @($PreviousAudit.Results)) { $PrevMap["$($p.Categorie)|$($p.Controle)"] = $p }

    foreach ($cur in $AuditResults) {
        $key = "$($cur.Categorie)|$($cur.Controle)"
        if ($PrevMap.ContainsKey($key)) {
            $prev = $PrevMap[$key]
            if ($prev.Statut -ne $cur.Statut) {
                $degrade = (@("FAIL","WARN") -contains $cur.Statut) -and (@("OK","INFO") -contains $prev.Statut)
                $ameliore = (@("OK","INFO") -contains $cur.Statut) -and (@("FAIL","WARN") -contains $prev.Statut)
                $Deltas.Add([PSCustomObject]@{
                    Categorie = $cur.Categorie; Controle = $cur.Controle
                    Avant = $prev.Statut; Apres = $cur.Statut
                    Type = if ($degrade) { "Nouveau problème" } elseif ($ameliore) { "Résolu" } else { "Changement" }
                })
            }
            $PrevMap.Remove($key)
        } elseif (@("FAIL","WARN") -contains $cur.Statut) {
            $Deltas.Add([PSCustomObject]@{ Categorie=$cur.Categorie; Controle=$cur.Controle; Avant="(nouveau contrôle)"; Apres=$cur.Statut; Type="Nouveau contrôle" })
        }
    }
    foreach ($remaining in $PrevMap.Values) {
        if (@("FAIL","WARN") -contains $remaining.Statut) {
            $Deltas.Add([PSCustomObject]@{ Categorie=$remaining.Categorie; Controle=$remaining.Controle; Avant=$remaining.Statut; Apres="(disparu)"; Type="Contrôle disparu" })
        }
    }

    $PrevScore = $PreviousAudit.Score
    $ScoreDiff = $Score - $PrevScore
    Write-Log "Évolution du score depuis le dernier audit ($($PreviousAudit.Date)) : $PrevScore -> $Score ($(if($ScoreDiff -ge 0){'+'})$ScoreDiff)" -Level $(if($ScoreDiff -ge 0){"OK"}else{"WARN"})

    # NOTE v4.0 : alerte régression — si le score recule de plus de
    # $ScoreRegressionThreshold points, on émet un FAIL en console pour
    # qu'une exécution planifiée (-Silent) le fasse ressortir dans les logs.
    if ($ScoreDiff -le -$ScoreRegressionThreshold) {
        Write-Log "ALERTE RÉGRESSION : le score a chuté de $([math]::Abs($ScoreDiff)) points ($PrevScore → $Score) — seuil configuré : $ScoreRegressionThreshold pts" -Level FAIL
    }
} else {
    Write-Log "Pas d'audit précédent trouvé — première exécution ou baseline absente, aucune comparaison possible" -Level INFO
}

# Sauvegarde du run courant comme référence pour la prochaine exécution
try {
    [PSCustomObject]@{
        Date    = Get-Date -Format "o"
        Score   = $Score
        Results = ($AuditResults | Select-Object Categorie, Controle, Valeur, Statut)
    } | ConvertTo-Json -Depth 5 | Out-File -FilePath $BaselineFile -Encoding UTF8 -Force
} catch {
    Write-Log "Impossible d'écrire la baseline pour la comparaison future : $($_.Exception.Message)" -Level WARN
}

# Export JSON complet du run courant (utilisable par d'autres outils/scripts)
try {
    [PSCustomObject]@{
        Machine       = $env:COMPUTERNAME
        Date          = Get-Date -Format "o"
        ScriptVersion = $ScriptVersion
        Score         = $Score
        Summary       = [PSCustomObject]@{ Total=$Total; OK=$TotalOK; WARN=$TotalWARN; FAIL=$TotalFAIL; INFO=$TotalINFO }
        Results       = $AuditResults
        Deltas        = $Deltas
    } | ConvertTo-Json -Depth 6 | Out-File -FilePath $ReportJSON -Encoding UTF8 -Force
} catch {
    Write-Log "Impossible d'écrire l'export JSON : $($_.Exception.Message)" -Level WARN
}

# NOTE v3.0 : export CSV pour exploitation rapide dans Excel/LibreOffice,
# en plus du TXT/JSON existants. Mêmes colonnes que le tableau du rapport HTML.
try {
    $AuditResults | Select-Object Categorie, Controle, Valeur, Statut, Detail |
        Export-Csv -Path $ReportCSV -NoTypeInformation -Encoding UTF8 -Delimiter ";"
} catch {
    Write-Log "Impossible d'écrire l'export CSV : $($_.Exception.Message)" -Level WARN
}

# NOTE v3.0 : historique multi-run, distinct du baseline (qui ne garde que le
# run précédent). On ajoute le run courant, on tronque aux $MaxHistoryRuns
# plus récents, et on réécrit le fichier en entier (pas d'append incrémental
# pour éviter un JSON invalide en cas d'interruption en cours d'écriture).
try {
    $ScoreHistory.Add([PSCustomObject]@{ Date = Get-Date -Format "o"; Score = $Score })
    $HistoryToKeep = $ScoreHistory | Select-Object -Last $MaxHistoryRuns
    $HistoryToKeep | ConvertTo-Json -Depth 3 | Out-File -FilePath $HistoryFile -Encoding UTF8 -Force
    $ScoreHistory = [System.Collections.Generic.List[object]]::new()
    foreach ($h in @($HistoryToKeep)) { $ScoreHistory.Add($h) }
} catch {
    Write-Log "Impossible d'écrire l'historique multi-run : $($_.Exception.Message)" -Level WARN
}

# ──────────────────────────────────────────────
#  GÉNÉRATION DU RAPPORT HTML
# ──────────────────────────────────────────────
Write-Log "Génération du rapport HTML : $ReportHTML" -Level INFO

# NOTE v4.2 : résumé exécutif — bloc "Points critiques" affiché en haut du
# rapport HTML, avant le tableau détaillé. Permet un coup d'œil immédiat sans
# devoir scroller. FAIL en premier (rouge), puis WARN (orange). Limité à 10
# éléments pour ne pas noyer la page. Si tout est OK/INFO : bandeau vert.
$CriticalItems = @(
    @($AuditResults | Where-Object { $_.Statut -eq "FAIL" }) +
    @($AuditResults | Where-Object { $_.Statut -eq "WARN" })
) | Select-Object -First 10

if ($CriticalItems.Count -eq 0) {
    $ExecSummaryHTML = @"
  <div class="exec-summary exec-ok">
    <span class="exec-icon">✅</span>
    <span><strong>Aucun problème détecté</strong> — Tous les contrôles sont au vert sur ce run.</span>
  </div>
"@
} else {
    $execItemsHTML = ""
    foreach ($item in $CriticalItems) {
        $itemClass = if ($item.Statut -eq "FAIL") { "exec-fail" } else { "exec-warn" }
        $itemIcon  = if ($item.Statut -eq "FAIL") { "✘" } else { "⚠" }
        $execItemsHTML += @"
    <div class="exec-item $itemClass">
      <span class="exec-badge">$itemIcon $($item.Statut)</span>
      <span class="exec-cat">$(He $item.Categorie)</span>
      <span class="exec-ctrl">$(He $item.Controle)</span>
      <span class="exec-val">$(He $item.Valeur)</span>
    </div>
"@
    }
    $moreNote = if (($AuditResults | Where-Object { $_.Statut -in "FAIL","WARN" }).Count -gt 10) {
        "<div class='exec-more'>… et $( ($AuditResults | Where-Object { $_.Statut -in 'FAIL','WARN' }).Count - 10 ) autre(s) — voir le tableau complet ci-dessous.</div>"
    } else { "" }
    $ExecSummaryHTML = @"
  <div class="exec-summary">
    <div class="exec-title">⚑ Points critiques ($TotalFAIL FAIL · $TotalWARN WARN)</div>
$execItemsHTML
$moreNote
  </div>
"@
}

# NOTE v5.0 : tableau de score par catégorie — expose le détail du calcul pondéré
# pour que l'utilisateur identifie immédiatement quelle catégorie tire le score
# vers le bas. Trié par score partiel croissant (les pires catégories en premier).
$CatScoreRows = ""
$CatScoreData = $CatStats.GetEnumerator() | ForEach-Object {
    $cat     = $_.Key
    $weight  = if ($CategoryWeights.ContainsKey($cat)) { $CategoryWeights[$cat] } else { 1.0 }
    $rate    = $_.Value.WeightedSum / $_.Value.Count
    $partial = [int][math]::Round($rate * 100)
    $count   = $_.Value.Count
    [PSCustomObject]@{ Cat=$cat; Weight=$weight; Rate=$rate; Partial=$partial; Count=$count }
} | Sort-Object Partial

foreach ($row in $CatScoreData) {
    $barColor = if ($row.Partial -ge 80) { "#27ae60" } elseif ($row.Partial -ge 50) { "#f39c12" } else { "#e74c3c" }
    $weightStr = "$($row.Weight.ToString('0.0'))"
    $CatScoreRows += @"
      <tr>
        <td class="cat-cell" style="white-space:nowrap">$($row.Cat)</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="flex:1;background:var(--surface2);border-radius:4px;height:10px;overflow:hidden">
              <div style="width:$($row.Partial)%;height:100%;background:$barColor;border-radius:4px"></div>
            </div>
            <span style="color:$barColor;font-weight:700;width:36px;text-align:right">$($row.Partial)%</span>
          </div>
        </td>
        <td style="color:var(--muted);text-align:center">$weightStr</td>
        <td style="color:var(--muted);text-align:center">$($row.Count)</td>
      </tr>
"@
}

$CatScoreTableHTML = @"
  <div class="delta-wrap">
    <div class="delta-header" style="margin-bottom:14px">
      <span class="section-title" style="margin:0">Score par catégorie</span>
      <span style="color:var(--muted);font-size:12px">Score global pondéré : <strong style="color:$ScoreColor">$Score / 100</strong></span>
    </div>
    <table style="margin:0">
      <thead>
        <tr>
          <th>Catégorie</th>
          <th>Score partiel</th>
          <th style="text-align:center">Poids</th>
          <th style="text-align:center">Contrôles</th>
        </tr>
      </thead>
      <tbody>
$CatScoreRows
      </tbody>
    </table>
  </div>
"@

# Bloc "Évolution depuis le dernier audit"
$DeltaSectionHTML = ""
if ($PreviousAudit -and $PreviousAudit.Results) {
    # NOTE v2.3 : ConvertFrom-Json sur PowerShell 7+ détecte automatiquement
    # les chaînes au format ISO-8601 (celles produites par "Get-Date -Format
    # 'o'") et les convertit en véritables objets [DateTime], pas en simples
    # chaînes — contrairement à l'hypothèse de la v2.0/2.1/2.2 qui appelait
    # .Substring() en supposant systématiquement une chaîne. Ça plantait avec
    # "Method invocation failed ... does not contain a method named 'Substring'"
    # dès que le JSON était relu. On formate désormais explicitement, que la
    # valeur soit un [DateTime] ou restée une [string] (cas d'un baseline plus
    # ancien, ou d'un environnement où la conversion auto ne se produit pas).
    $PrevDateDisplay = try {
        if ($PreviousAudit.Date -is [DateTime]) {
            $PreviousAudit.Date.ToString("dd/MM/yyyy HH:mm")
        } else {
            ([DateTime]::Parse("$($PreviousAudit.Date)")).ToString("dd/MM/yyyy HH:mm")
        }
    } catch {
        "$($PreviousAudit.Date)"
    }

    $ScoreDiff = $Score - [int]$PreviousAudit.Score
    $diffClass = if ($ScoreDiff -gt 0) { "up" } elseif ($ScoreDiff -lt 0) { "down" } else { "flat" }
    $diffText  = if ($ScoreDiff -gt 0) { "+$ScoreDiff" } else { "$ScoreDiff" }

    # NOTE v4.0 : bannière rouge de régression — affichée seulement si le
    # recul dépasse $ScoreRegressionThreshold, au-dessus du bloc Évolution.
    $RegressionBannerHTML = ""
    if ($ScoreDiff -le -$ScoreRegressionThreshold) {
        $absDiff = [math]::Abs($ScoreDiff)
        $RegressionBannerHTML = @"
  <div class="regression-banner">
    <span class="regression-icon">⚠</span>
    <span><strong>Alerte régression</strong> — Le score a chuté de <strong>$absDiff points</strong> depuis le dernier audit ($([int]$PreviousAudit.Score) → $Score). Consultez les nouveaux problèmes ci-dessous.</span>
  </div>
"@
    }
    $deltaItemsHTML = ""
    if ($Deltas.Count -eq 0) {
        $deltaItemsHTML = "<div class='delta-empty'>Aucun changement de statut depuis le dernier audit.</div>"
    } else {
        foreach ($d in $Deltas) {
            $tagClass = switch ($d.Type) {
                "Nouveau problème"  { "worse" }
                "Résolu"            { "better" }
                "Contrôle disparu"  { "neutral" }
                "Nouveau contrôle"  { "neutral" }
                default             { "neutral" }
            }
            $deltaItemsHTML += @"
            <div class="delta-item $tagClass">
              <span class="tag">$($d.Type)</span>
              <span>$($d.Categorie) — $($d.Controle)</span>
              <span class="arrow">$($d.Avant) → $($d.Apres)</span>
            </div>
"@
        }
    }

    $DeltaSectionHTML = @"
  $RegressionBannerHTML
  <div class="delta-wrap">
    <div class="delta-header">
      <span class="section-title" style="margin:0">Évolution depuis le dernier audit ($PrevDateDisplay)</span>
      <span class="delta-score-diff $diffClass">$([int]$PreviousAudit.Score) → $Score ($diffText)</span>
    </div>
    <div class="delta-list">
      $deltaItemsHTML
    </div>
  </div>
"@
}

# NOTE v3.0 : mini-graphique SVG (sparkline) de l'évolution du score sur les
# derniers runs, basé sur $ScoreHistory (fichier distinct du baseline, voir
# section CONFIGURATION). Coordonnées formatées en InvariantCulture — pattern
# déjà établi dans la suite (Check-Boot) pour éviter une virgule décimale sur
# un Windows en locale FR, qui invaliderait l'attribut "points" du SVG.
$HistoryChartHTML = ""
if ($ScoreHistory.Count -ge 2) {
    $Inv = [System.Globalization.CultureInfo]::InvariantCulture
    $ChartW = 600; $ChartH = 80; $Pad = 8
    $HistScores = @($ScoreHistory | ForEach-Object { [int]$_.Score })
    $MinS = ($HistScores | Measure-Object -Minimum).Minimum
    $MaxS = ($HistScores | Measure-Object -Maximum).Maximum
    if ($MaxS -eq $MinS) { $MaxS = $MinS + 1 }
    $StepX = ($ChartW - 2 * $Pad) / [math]::Max(1, ($HistScores.Count - 1))

    $Points = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $HistScores.Count; $i++) {
        $x = $Pad + ($i * $StepX)
        $yRatio = ($HistScores[$i] - $MinS) / [double]($MaxS - $MinS)
        $y = $ChartH - $Pad - ($yRatio * ($ChartH - 2 * $Pad))
        $Points.Add("$($x.ToString('0.##', $Inv)),$($y.ToString('0.##', $Inv))")
    }
    $PolylinePoints = $Points -join " "
    $LastX = $Points[-1].Split(',')[0]
    $LastY = $Points[-1].Split(',')[1]

    $HistoryChartHTML = @"
  <div class="delta-wrap">
    <div class="delta-header">
      <span class="section-title" style="margin:0">Historique des scores ($($ScoreHistory.Count) derniers runs)</span>
      <span class="detail">Min $MinS — Max $MaxS</span>
    </div>
    <svg viewBox="0 0 $ChartW $ChartH" width="100%" height="$ChartH" preserveAspectRatio="none">
      <polyline points="$PolylinePoints" fill="none" stroke="var(--accent)" stroke-width="2" />
      <circle cx="$LastX" cy="$LastY" r="3.5" fill="$ScoreColor" />
    </svg>
  </div>
"@
}

# NOTE v4.3 : DeltaMap — table de lookup Categorie|Controle → type de delta,
# construite à partir de $Deltas (calculé dans la section ÉVOLUTION ci-dessus).
# Utilisée lors de la génération des <tr> pour afficher l'icône Δ inline.
$DeltaMap = @{}
foreach ($d in $Deltas) {
    $DeltaMap["$($d.Categorie)|$($d.Controle)"] = $d.Type
}

# Grouper par catégorie
$Categories = $AuditResults | Select-Object -ExpandProperty Categorie -Unique

# NOTE v3.0 : ancres + attributs data-* pour le filtre JS et les liens directs
# vers les contrôles critiques (voir bloc <script> plus bas). Chaque ligne FAIL
# reçoit un id unique ("fail-N") référencé par la liste de liens en haut du rapport.
$TableRows = ""
$FailAnchorsHTML = ""
$FailCounter = 0
foreach ($cat in $Categories) {
    $items = $AuditResults | Where-Object { $_.Categorie -eq $cat }
    $first = $true
    foreach ($item in $items) {
        $rowClass = switch ($item.Statut) {
            "FAIL" { "row-fail" }
            "WARN" { "row-warn" }
            "OK"   { "row-ok"   }
            default { "" }
        }
        $catCell = if ($first) {
            "<td class='cat-cell' rowspan='$($items.Count)'>$cat</td>"
            $first = $false
        } else { "" }

        $detail = if ($item.Detail) { "<br><small class='detail'>$($item.Detail)</small>" } else { "" }

        # NOTE v3.2 : liens d'aide contextuels uniquement sur les contrôles
        # WARN/FAIL — un contrôle OK/INFO n'a pas besoin de documentation
        # de remédiation, ça alourdirait le tableau pour rien.
        # Exception : deux catégories INFO méritent quand même des liens :
        # - Logiciels : la recherche CVE (NVD) est utile même si le statut
        #   est INFO (on n'a pas de comparaison de version en temps réel).
        # - Certificats : le lien crt.sh (recherche par empreinte) est utile
        #   même sur les certificats individuels détaillés classés en INFO.
        $helpLinks = ""
        $needsLinks = $item.Statut -in @("WARN","FAIL") -or
                      ($item.Statut -eq "INFO" -and $item.Categorie -eq "Logiciels" -and $item.Controle -like "Logiciel à surveiller :*") -or
                      ($item.Statut -eq "INFO" -and $item.Categorie -eq "Certificats" -and $item.Controle -like "Certificat racine :*")
        if ($needsLinks) {
            $helpLinks = Get-HelpLinks -Categorie $item.Categorie -Controle $item.Controle -Valeur $item.Valeur -Detail $item.Detail
        }

        $rowId = ""
        if ($item.Statut -eq "FAIL") {
            $FailCounter++
            $rowId = "fail-$FailCounter"
            $FailAnchorsHTML += "<a href=`"#$rowId`" class=`"fail-link`">$($item.Categorie) — $($item.Controle)</a>"
        }

        $searchText = ("$($item.Categorie) $($item.Controle) $($item.Valeur) $($item.Detail)").ToLower() -replace '"','&quot;'

        # NOTE v4.3 : icône Δ inline — croisement avec $DeltaMap
        $deltaKey  = "$($item.Categorie)|$($item.Controle)"
        $deltaIcon = ""
        if ($DeltaMap.ContainsKey($deltaKey)) {
            $deltaIcon = switch ($DeltaMap[$deltaKey]) {
                "Nouveau problème" { " <span class='delta-inline worse' title='Dégradé depuis le dernier audit'>▲</span>" }
                "Résolu"           { " <span class='delta-inline better' title='Amélioré depuis le dernier audit'>▼</span>" }
                "Nouveau contrôle" { " <span class='delta-inline neutral' title='Nouveau contrôle'>●</span>" }
                "Contrôle disparu" { "" }
                default            { "" }
            }
        }

        $TableRows += @"
        <tr class="$rowClass" id="$rowId" data-status="$($item.Statut)" data-search="$searchText">
            $catCell
            <td>$($item.Controle)</td>
            <td>$($item.Valeur)$detail$helpLinks</td>
            <td>$(Get-StatusBadge $item.Statut)$deltaIcon</td>
        </tr>
"@
    }
}

# NOTE v3.0 : bloc de liens directs vers les contrôles en FAIL, affiché en
# haut du rapport seulement s'il y en a au moins un — sinon on n'affiche rien
# plutôt qu'un encadré vide.
$FailAnchorsBlockHTML = ""
if ($FailCounter -gt 0) {
    $FailAnchorsBlockHTML = @"
  <div class="delta-wrap">
    <p class="section-title">Accès direct aux contrôles critiques ($FailCounter)</p>
    <div class="fail-links">
      $FailAnchorsHTML
    </div>
  </div>
"@
}


$HTML = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Audit Sécurité Windows 11 — $env:COMPUTERNAME</title>
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d27; --surface2: #222535;
    --border: #2e3147; --text: #e2e8f0; --muted: #8892a4;
    --ok: #27ae60; --warn: #f39c12; --fail: #e74c3c; --info: #3498db;
    --accent: #6366f1;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.5; }

  header { background: linear-gradient(135deg, #1e2035 0%, #12141f 100%); border-bottom: 1px solid var(--border); padding: 32px 40px; }
  header h1 { font-size: 26px; font-weight: 700; letter-spacing: -0.5px; margin-bottom: 4px; }
  header h1 span { color: var(--accent); }
  header p { color: var(--muted); font-size: 13px; }

  .container { max-width: 1400px; margin: 0 auto; padding: 32px 40px; }

  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 32px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }
  .stat-card .num { font-size: 36px; font-weight: 800; line-height: 1; margin-bottom: 6px; }
  .stat-card .lbl { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-card.ok   .num { color: var(--ok);   }
  .stat-card.warn .num { color: var(--warn);  }
  .stat-card.fail .num { color: var(--fail);  }
  .stat-card.info .num { color: var(--info);  }
  .stat-card.score .num { color: $ScoreColor; }

  .section-title { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 12px; }

  table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; margin-bottom: 32px; }
  thead th { background: var(--surface2); padding: 12px 16px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); border-bottom: 1px solid var(--border); }
  tbody td { padding: 10px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:last-child td { border-bottom: none; }
  .cat-cell { color: var(--accent); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; background: var(--surface2); border-right: 1px solid var(--border); vertical-align: top; white-space: nowrap; }
  .row-fail { background: rgba(231,76,60,0.05); }
  .row-warn { background: rgba(243,156,18,0.05); }
  .row-ok   { background: rgba(39,174,96,0.03);  }
  .detail   { color: var(--muted); }

  .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; white-space: nowrap; }
  .badge.ok   { background: rgba(39,174,96,0.15);  color: var(--ok);   border: 1px solid rgba(39,174,96,0.3);  }
  .badge.warn { background: rgba(243,156,18,0.15); color: var(--warn); border: 1px solid rgba(243,156,18,0.3); }
  .badge.fail { background: rgba(231,76,60,0.15);  color: var(--fail); border: 1px solid rgba(231,76,60,0.3);  }
  .badge.info { background: rgba(52,152,219,0.15); color: var(--info); border: 1px solid rgba(52,152,219,0.3); }

  .score-bar-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 32px; }
  .score-bar-track { background: var(--surface2); border-radius: 8px; height: 18px; overflow: hidden; margin-top: 10px; }
  .score-bar-fill { height: 100%; border-radius: 8px; background: linear-gradient(90deg, $ScoreColor, ${ScoreColor}99); width: ${Score}%; transition: width 1s; }
  .score-label { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .score-label span:first-child { font-weight: 700; font-size: 16px; }
  .score-value { font-size: 28px; font-weight: 800; color: $ScoreColor; }

  footer { text-align: center; padding: 24px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 16px; }

  .delta-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 32px; }
  .delta-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
  .delta-score-diff { font-size: 20px; font-weight: 800; }
  .delta-score-diff.up   { color: var(--ok);   }
  .delta-score-diff.down { color: var(--fail); }
  .delta-score-diff.flat { color: var(--muted); }
  .delta-list { display: flex; flex-direction: column; gap: 8px; }
  .delta-item { display: flex; align-items: center; gap: 10px; padding: 10px 14px; border-radius: 8px; background: var(--surface2); font-size: 13px; }
  .delta-item .tag { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; padding: 2px 8px; border-radius: 6px; white-space: nowrap; }
  .delta-item.worse .tag { background: rgba(231,76,60,0.18); color: var(--fail); }
  .delta-item.better .tag { background: rgba(39,174,96,0.18); color: var(--ok); }
  .delta-item.neutral .tag { background: rgba(52,152,219,0.18); color: var(--info); }
  .delta-item .arrow { color: var(--muted); }
  .delta-empty { color: var(--muted); font-size: 13px; }

  .fail-links { display: flex; flex-wrap: wrap; gap: 8px; }
  .fail-link { font-size: 12px; padding: 6px 12px; border-radius: 20px; background: rgba(231,76,60,0.12); color: var(--fail); border: 1px solid rgba(231,76,60,0.3); text-decoration: none; white-space: nowrap; }

  .help-links { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 6px; }
  .help-link { font-size: 11px; padding: 3px 10px; border-radius: 12px; background: var(--surface2); color: var(--accent); border: 1px solid var(--border); text-decoration: none; white-space: nowrap; }
  .help-link:hover { background: var(--accent); color: white; border-color: var(--accent); }
  .help-link::before { content: "🔗 "; }
  .fail-link:hover { background: rgba(231,76,60,0.22); }

  .search-box { width: 100%; max-width: 420px; margin-bottom: 16px; padding: 10px 14px; border-radius: 8px; border: 1px solid var(--border); background: var(--surface); color: var(--text); font-size: 13px; }
  .search-box:focus { outline: none; border-color: var(--accent); }
  .filter-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
  .filter-chip { font-size: 11px; padding: 5px 12px; border-radius: 20px; border: 1px solid var(--border); background: var(--surface2); color: var(--muted); cursor: pointer; user-select: none; }
  .filter-chip.active { background: var(--accent); color: white; border-color: var(--accent); }
  .no-results { color: var(--muted); font-size: 13px; padding: 16px; text-align: center; display: none; }

  .regression-banner { display: flex; align-items: center; gap: 14px; background: rgba(231,76,60,0.12); border: 1px solid rgba(231,76,60,0.4); border-radius: 12px; padding: 16px 20px; margin-bottom: 16px; color: var(--fail); }
  .regression-icon { font-size: 22px; flex-shrink: 0; }

  .exec-summary { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; margin-bottom: 20px; }
  .exec-summary.exec-ok { border-color: rgba(39,174,96,0.4); background: rgba(39,174,96,0.07); display: flex; align-items: center; gap: 12px; color: var(--ok); }
  .exec-icon { font-size: 20px; }
  .exec-title { font-weight: 600; font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 10px; }
  .exec-item { display: grid; grid-template-columns: 80px 130px 1fr auto; gap: 10px; align-items: center; padding: 8px 10px; border-radius: 8px; margin-bottom: 5px; font-size: 13px; }
  .exec-item.exec-fail { background: rgba(231,76,60,0.08); }
  .exec-item.exec-warn { background: rgba(243,156,18,0.08); }
  .exec-badge { font-weight: 700; font-size: 11px; }
  .exec-item.exec-fail .exec-badge { color: var(--fail); }
  .exec-item.exec-warn .exec-badge { color: var(--warn); }
  .exec-cat { color: var(--muted); font-size: 11px; }
  .exec-ctrl { color: var(--text); }
  .exec-val { color: var(--muted); font-size: 11px; text-align: right; }
  .exec-more { font-size: 12px; color: var(--muted); text-align: center; margin-top: 8px; }

  .delta-inline { font-size: 11px; margin-left: 6px; font-weight: 700; vertical-align: middle; }
  .delta-inline.worse   { color: var(--fail); }
  .delta-inline.better  { color: var(--ok); }
  .delta-inline.neutral { color: var(--muted); }
</style>
</head>
<body>
<header>
  <h1>🛡️ Audit Sécurité <span>Windows 11</span></h1>
  <p>Machine : <strong>$env:COMPUTERNAME</strong> &nbsp;|&nbsp; Date : <strong>$(Get-Date -Format "dd/MM/yyyy HH:mm")</strong> &nbsp;|&nbsp; Script v$ScriptVersion &nbsp;|&nbsp; OS : $($OS.Caption) Build $($OS.BuildNumber)</p>
</header>
<div class="container">

  <!-- Score -->
  <div class="score-bar-wrap">
    <div class="score-label">
      <span>Score de sécurité global</span>
      <span class="score-value">$Score / 100</span>
    </div>
    <div class="score-bar-track"><div class="score-bar-fill"></div></div>
  </div>

  $DeltaSectionHTML

  $FailAnchorsBlockHTML

  $HistoryChartHTML

  <!-- Résumé -->
  <p class="section-title">Résumé des contrôles</p>
  <div class="summary-grid">
    <div class="stat-card score"><div class="num">$Total</div><div class="lbl">Total contrôles</div></div>
    <div class="stat-card ok">  <div class="num">$TotalOK</div>  <div class="lbl">OK</div></div>
    <div class="stat-card warn"><div class="num">$TotalWARN</div><div class="lbl">Attention</div></div>
    <div class="stat-card fail"><div class="num">$TotalFAIL</div><div class="lbl">Critique</div></div>
    <div class="stat-card info"><div class="num">$TotalINFO</div><div class="lbl">Info</div></div>
  </div>

  <!-- Résumé exécutif — Points critiques (v4.2) -->
  $ExecSummaryHTML

  <!-- Score par catégorie (v5.0) -->
  $CatScoreTableHTML

  <!-- Tableau complet -->
  <p class="section-title">Résultats détaillés</p>
  <input type="text" id="searchBox" class="search-box" placeholder="🔎 Rechercher (catégorie, contrôle, valeur, détail)…">
  <div class="filter-bar">
    <span class="filter-chip active" data-filter="ALL">Tous</span>
    <span class="filter-chip" data-filter="FAIL">Critique</span>
    <span class="filter-chip" data-filter="WARN">Attention</span>
    <span class="filter-chip" data-filter="OK">OK</span>
    <span class="filter-chip" data-filter="INFO">Info</span>
  </div>
  <table id="resultsTable">
    <thead>
      <tr>
        <th style="width:130px">Catégorie</th>
        <th style="width:280px">Contrôle</th>
        <th>Valeur / Description</th>
        <th style="width:120px">Statut</th>
      </tr>
    </thead>
    <tbody>
      $TableRows
    </tbody>
  </table>
  <p class="no-results" id="noResults">Aucun résultat ne correspond à ce filtre.</p>
</div>
<footer>Rapport généré automatiquement par Check-Security_Win11.ps1 v$ScriptVersion — $env:COMPUTERNAME — $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")</footer>
<script>
  // NOTE v3.0 : recherche/filtre client-side, même pattern que Block-Telemetry v5.
  // Pas de dépendance externe ; tout repose sur les attributs data-status /
  // data-search posés sur chaque <tr> côté PowerShell.
  (function () {
    var searchBox = document.getElementById('searchBox');
    var chips = document.querySelectorAll('.filter-chip');
    var rows = document.querySelectorAll('#resultsTable tbody tr');
    var noResults = document.getElementById('noResults');
    var activeStatus = 'ALL';

    function applyFilters() {
      var term = (searchBox.value || '').toLowerCase().trim();
      var visibleCount = 0;
      rows.forEach(function (row) {
        var matchesStatus = (activeStatus === 'ALL') || (row.getAttribute('data-status') === activeStatus);
        var matchesSearch = !term || (row.getAttribute('data-search') || '').indexOf(term) !== -1;
        var show = matchesStatus && matchesSearch;
        row.style.display = show ? '' : 'none';
        if (show) visibleCount++;
      });
      noResults.style.display = (visibleCount === 0) ? 'block' : 'none';
    }

    searchBox.addEventListener('input', applyFilters);
    chips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        chips.forEach(function (c) { c.classList.remove('active'); });
        chip.classList.add('active');
        activeStatus = chip.getAttribute('data-filter');
        applyFilters();
      });
    });
  })();
</script>
</body>
</html>
"@

$HTML | Out-File -FilePath $ReportHTML -Encoding UTF8 -Force

# ──────────────────────────────────────────────
#  AFFICHAGE FINAL
# ──────────────────────────────────────────────
# NOTE v2.2 : alignement avec le comportement de SpicyCheck-v7.0 — le rapport
# n'est plus ouvert automatiquement (on le PROPOSE via une question O/n), et
# la fenêtre console ne se ferme plus toute seule à la fin (pause ENTRÉE),
# pour laisser le temps de lire le résumé avant que la fenêtre disparaisse.
# Comme pour le reste du script, tout ceci est sauté en mode -Silent.
if (-not $Silent) {
    $scoreColor = if ($Score -ge 80) { "Green" } elseif ($Score -ge 50) { "Yellow" } else { "Red" }
    $barWidth = 62

    # NOTE v5.0.9 : même style de cadre ╔═╗ que les bannières de section,
    # pour une cohérence visuelle de bout en bout du script.
    Write-Host ""
    Write-Host ("╔" + ("═" * $barWidth) + "╗") -ForegroundColor Cyan
    Write-Host "║" -NoNewline -ForegroundColor Cyan
    Write-Host (" ✓ AUDIT TERMINÉ").PadRight($barWidth) -NoNewline -ForegroundColor Green
    Write-Host "║" -ForegroundColor Cyan
    Write-Host ("╚" + ("═" * $barWidth) + "╝") -ForegroundColor Cyan
    Write-Host ""

    # Mini-jauge visuelle du score (20 blocs), même seuils de couleur que le HTML.
    $gaugeBlocks = 20
    $filled = [math]::Round(($Score / 100) * $gaugeBlocks)
    $gauge = ("█" * $filled) + ("░" * ($gaugeBlocks - $filled))
    Write-Host "   Score de sécurité  " -NoNewline -ForegroundColor Gray
    Write-Host "$gauge" -NoNewline -ForegroundColor $scoreColor
    Write-Host "  $Score/100" -ForegroundColor $scoreColor

    Write-Host "   Contrôles          " -NoNewline -ForegroundColor Gray
    Write-Host "$Total total" -NoNewline -ForegroundColor White
    Write-Host "  ·  " -NoNewline -ForegroundColor DarkGray
    Write-Host "✓ $TotalOK OK" -NoNewline -ForegroundColor Green
    Write-Host "  ·  " -NoNewline -ForegroundColor DarkGray
    Write-Host "! $TotalWARN WARN" -NoNewline -ForegroundColor Yellow
    Write-Host "  ·  " -NoNewline -ForegroundColor DarkGray
    Write-Host "✗ $TotalFAIL FAIL" -ForegroundColor Red

    if ($PreviousAudit -and $PreviousAudit.Results) {
        $ScoreDiffDisplay = $Score - [int]$PreviousAudit.Score
        $diffStr = if ($ScoreDiffDisplay -ge 0) { "+$ScoreDiffDisplay" } else { "$ScoreDiffDisplay" }
        $diffColor = if ($ScoreDiffDisplay -ge 0) { "Green" } else { "Yellow" }
        Write-Host "   Évolution          " -NoNewline -ForegroundColor Gray
        Write-Host "$diffStr point(s)" -NoNewline -ForegroundColor $diffColor
        Write-Host "  ($($Deltas.Count) changement(s) de statut depuis le dernier audit)" -ForegroundColor DarkGray
    }

    # NOTE v4.7 : détail FAIL/WARN dans le bandeau console — jusqu'à 5 de chaque
    # pour un coup d'œil immédiat sans ouvrir le rapport HTML.
    $FailItems = @($AuditResults | Where-Object { $_.Statut -eq "FAIL" })
    $WarnItems = @($AuditResults | Where-Object { $_.Statut -eq "WARN" })

    if ($FailItems.Count -gt 0) {
        Write-Host ""
        Write-Host "   ✗ FAIL" -ForegroundColor Red
        $FailItems | Select-Object -First 5 | ForEach-Object {
            Write-Host "      • [$($_.Categorie)] $($_.Controle) : $($_.Valeur)" -ForegroundColor Red
        }
        if ($FailItems.Count -gt 5) { Write-Host "      … et $($FailItems.Count - 5) autre(s)" -ForegroundColor DarkRed }
    }
    if ($WarnItems.Count -gt 0) {
        Write-Host ""
        Write-Host "   ! WARN" -ForegroundColor Yellow
        $WarnItems | Select-Object -First 5 | ForEach-Object {
            Write-Host "      • [$($_.Categorie)] $($_.Controle) : $($_.Valeur)" -ForegroundColor Yellow
        }
        if ($WarnItems.Count -gt 5) { Write-Host "      … et $($WarnItems.Count - 5) autre(s)" -ForegroundColor DarkYellow }
    }

    Write-Host ""
    Write-Host "   »  Rapport HTML  " -NoNewline -ForegroundColor DarkGray
    Write-Host "$ReportHTML" -ForegroundColor Cyan
    Write-Host "   »  Rapport TXT   " -NoNewline -ForegroundColor DarkGray
    Write-Host "$ReportTXT" -ForegroundColor Cyan
    Write-Host "   »  Export JSON   " -NoNewline -ForegroundColor DarkGray
    Write-Host "$ReportJSON" -ForegroundColor Cyan
    Write-Host "   »  Export CSV    " -NoNewline -ForegroundColor DarkGray
    Write-Host "$ReportCSV" -ForegroundColor Cyan
    Write-Host ("─" * ($barWidth + 2)) -ForegroundColor DarkCyan
    Write-Host ""

    if ($ReportHTML -and (Test-Path $ReportHTML)) {
        $OpenAnswer = Read-Host "  Ouvrir le rapport dans le navigateur ? [O/n]"
        if ($OpenAnswer -eq '' -or $OpenAnswer -match '^[OoYy]') {
            Start-Process $ReportHTML
        }
    }

    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║" -ForegroundColor Cyan -NoNewline
    Write-Host "  Appuyez sur ENTRÉE pour fermer cette fenêtre...    " -ForegroundColor Yellow -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Read-Host | Out-Null
}


# SIG # Begin signature block
# MIIFwgYJKoZIhvcNAQcCoIIFszCCBa8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBfYKzQVe3iUfU2
# A07EtV94IXUfvGyFobMjtzfqNwoTVqCCAygwggMkMIICDKADAgECAhB6X4r8AlBU
# p0MV3JpMuQ6sMA0GCSqGSIb3DQEBCwUAMCoxKDAmBgNVBAMMH05lcGhyZW4gUG93
# ZXJTaGVsbCBDb2RlIFNpZ25pbmcwHhcNMjYwNzA0MDIzMzIwWhcNMzEwNzA0MDI0
# MzIwWjAqMSgwJgYDVQQDDB9OZXBocmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5n
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JnV5AocUnAMNIG3nYF9
# 5mOQz5NzMYJqc9D6mq3pjRlmuYIgvYEuJL5dvt8eoAiUKd+XHTaY5wl+zt7LUon+
# TmEldVwfrYvROpI+5TDyBRc5BzY4uACsA4JUM4ienjX04BBKT3uH6JwHzBluWqcG
# Xrg16NqzDiae7WNzVrev+BME00mgSvBo3hKp3sHIvFQaAmjGXLyJd+llfnBpmoD9
# JnOxMKO7VFIlhAz5cEUnFu/xDLHgARdBUfXA5odScWKiDvygNZsH1vHo07Oo7pDK
# awR3bT6lcXWRXSUmawgE1mZra+b9qpeNol+5J+86zN83RccBKZBUtQQoyy+cv20x
# VQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# HQYDVR0OBBYEFNxVaDYoNv8UXQWnbtEy/DTaQHjYMA0GCSqGSIb3DQEBCwUAA4IB
# AQCE4NqZbeximmbNEORyLxvIYiMQwP59B9R95blQQ/zugPSt4wab61yBbgO1E3mH
# mUdN0fCHhN/u0uB7h7ZBYw1w4hnzoiBac4UYzsXH4/D41gBjutbtDllRy6/zs3dl
# /hbbHAmwKXdjNVLG9cPkpWlkvKR1DJLMugU2uj+S6k+U7DfHo76sbAKqiu3biXtd
# mao6PP99EU7JBYZjsJ+BsnYcZ2KcnZ8TKiRuhSXoxAyPman7Z0BVo1H2O+fxd96b
# 4W8VclmpFh7T2CyRAHolwEy5coFYyueisO0PZg+nKwXr66+m1T1CBLQYwh79/SKO
# wGUJyU5RtTryD+hfLwkTQKVCMYIB8DCCAewCAQEwPjAqMSgwJgYDVQQDDB9OZXBo
# cmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5nAhB6X4r8AlBUp0MV3JpMuQ6sMA0G
# CWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEIO9xZGcbcD8pyRzT2uzmtUUd53/rdT6JKDWTfwtV
# FOmjMA0GCSqGSIb3DQEBAQUABIIBAM1XRHumk4X6eUJCT7wNMiMo79JCCU+3jiYx
# Fvr0wfoEVt6OnfkzswZBTLmUC9YjktTVCdhFA8yB+nBueGniA8wBbPA6Tr/r94q1
# 8K6/SlS9dOKdiOyQbHetU/Z4yXXs+KIUv+pyZ2jhHV0WofqEsSIyPTheAieDCuGR
# p9Dts9dhlgfFPBJLRSgRSuY4B8TJgbvkVB42Y5EpUiBWotaOK5RTFIJUwApkERyF
# AD/3iPXm38JaF258mrC2LfcVnThaeaQF5y2/IPLPPJ8Js2xQwnEmuADYpaslXjPa
# 3F1l4dsSWi6ZBab73hV5sxeMF0d35oA71EvbIe/C6Le1QA/3HIA=
# SIG # End signature block
