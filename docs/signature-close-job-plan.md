# Plan d’update — fermeture auto + réouverture manuelle

> Statut: **implémenté** (academics + attendance)

## Objectif
- Fermer automatiquement la signature d’un cours après le délai configuré.
- Autoriser une réouverture manuelle qui **ignore tous les jobs suivants**.

## 1) Schéma (Academics DB)
- Ajouter un champ `signature_closed_override` (boolean) sur `courses`.
  - `false` par défaut.
  - Quand `true`, le job n’a **pas** le droit de refermer le cours.

## 2) Patch course (réouverture manuelle)
- `PATCH /course/{courseId}` :
  - Si `signatureClosed` passe à `false` → `signature_closed_override = true`.
  - Si `signatureClosed` passe à `true` → `signature_closed_override = false`.
- Le reste du payload ne change pas.

## 3) Job de fermeture automatique (Attendance)
- Job périodique (ticker) côté `attendance`.
- Appel gRPC vers `academics` avec un “close expired” (command).
- Règle de fermeture :
  - `signature_closed = false`
  - `signature_closed_override = false`
  - `start_at + signature_closing_delay_minutes < now()`

## 4) gRPC côté Academics (command minimal)
- Nouveau service/endpoint gRPC “command” pour fermer les cours expirés.
- SQL idempotent :
  - Update seulement les cours qui remplissent la règle.
  - Retourner un compteur (optionnel) pour log/debug.

## 5) Migration & SQL
- Migration `academics` pour ajouter `signature_closed_override`.
- Mise à jour des requêtes `UpdateCourse` et `GetCourse` si nécessaire.

## 6) Comportement attendu
- Réouverture manuelle **bloque définitivement** la fermeture auto.
- Fermeture manuelle réactive le job (override repasse à `false`).

## 7) Configuration
- `SIGNATURE_CLOSE_JOB_ENABLED=true|false` (activer/désactiver le job).
- `SIGNATURE_CLOSE_JOB_INTERVAL=1m` (fréquence du job, ex. `1m`, `5m`).
- `SIGNATURE_CLOSE_JOB_TIMEOUT=10s` (timeout gRPC par tick, ex. `5s`, `30s`).

## 8) Déploiement
- Appliquer la migration `academics`.
- Déployer academics + attendance (job activé par défaut).
