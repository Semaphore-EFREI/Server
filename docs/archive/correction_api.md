Ajouts
Les éléments suivants ont été corrigés dans le Swagger (https://swagger-editor.lebonnec.uk/) et doivent être implémentés :

Changement des propriétés du Token access_token et refresh_token en accessToken et refreshToken (camelCase)

Ajout de POST /auth/logout (modif sur swagger)

Suppression du paramètre "userType" pour /auth/refreshToken ( modif sur swagger, déjà fait sur server)

GET /courses : Les Admin et Dev peuvent l'appeler (pour l'instant c'est erreur 401 unauthorized) sans passer de ?userId=machinchose pour obtenir tous les cours programmés pour l'école sur la période demandée !important

POST /signature : Image non obligatoire pour les signatures d'enseignants

POST /signature : Paramètre "administrator" optionnel ajouté dans la signature d'enseignant, au cas où un admin mettrait présent l'enseignant manuellement

POST /course : Ajout de paramètres optionnels lorsque l'on crée un cours : !important

classroomsId : Liste d'id de salles

teachersId : Liste d'id d'enseignants

studentsId : Liste d'id d'étudiants seuls (à placer dans des groupes avec un seul étudiant)

studentGroupsId : Liste d'id de groupe d'étudiant 

GET /schools et GET /school/{schoolId} : Modification des champs des paramètres de l'école

GET /beacons et /beacon/{beaconId} : les admin peuvent maintenant obtenir la liste des balises de leur école !important

GET /courses et GET /course/{courseId} : Ajout de champs à l'objet CourseExtended :

students : Liste d'étudiants assistant au cours, qu'il fasse parti d'un groupe ou non

soloStudents : Liste d'étudiant assistant au cours mais n'ayant pas de groupe

studentGroups : Liste de groupes d'étudiants ayant été assignés au cours

Création de POST /course/{courseId}/students et DELETE /course/{courseId}/student/{studentId}, qui permettent d'ajouter et de supprimer des étudiants seuls (sans groupe) à un cours (en arrière plan, cela crée un groupe avec un seul étudiant, mais cela doit rester transparent pour l'API et le client)

POST /classroom : Ajout d'un paramètre (liste) permettant d'ajouter des balises à une salle en même temps que sa création

PATCH /school/{schoolId}/preferences : ajout d'un paramètre "disableCourseModificationFromUI" et le paramètre : "qrCodeEnabled" doit être enlevé



Points à vérifier

GET /schools/{schoolId} : doit accepter un paramètre expand et retourner l'objet contenant les préférence de l'école si celui-ci est demandé

POST /signature : Vérifier qu'un admin ou un enseignant peut mettre présent un élève manuellement sans fournir de challenge (qu'il ne peut de toute façon pas avoir)

POST /student : pourquoi ne peut-on donner que les champs obligatoires sinon erreur ? Autant enlever les champs optionnels de Swagger, peut-être. A voir avec Thomas pls

GET /studentGroups/{schoolId} : vérifier que les champs de la requête correspondent à ce qu'il y a sur Swagger (tests non concluants erreur 404) !important

POST /refreshToken : Faudrait-il rajouter userId comme paramètre? A discuter avec Thomas

POST /auth/logout : y-a-t-il un paramètre requis non indiqué dans le swagger ? (tests non concluants erreur 400) 

POST /admin : valeurs acceptées de "role" : planning / absence / manager (aligné Swagger) 

PATCH /student ou /teacher ou /admin : il doit y avoir un problème, erreur 400 systématique depuis ce matin 
