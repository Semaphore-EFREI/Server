Le serveur est la colonne vertebrale du service. Il se doit d'être sans bugs au niveau des signatures, constamment allumé (même lorsqu'il est mis à jour), et sans faille sur les services critiques.



Base de données
La base de données ressemble actuellement à ceci :






Utilisateurs
Chaque utilisateur à son propre type, et hérite de la même base d'informations que User.
Enseignants et étudiants en cours
Étant donnée que plusieurs enseignants peuvent donner un cours, un objet intermédiaire TeacherCoursers est utilisé.
Pour les étudiants, la situation est plus complexe. Pour rendre les choses pratiques pour l'administration, on peut créer des classes avec un StudentGroup. Étant donné que plusieurs étudiants peuvent être dans plusieurs classes (une classe de spécialité et une classe d'anglais par exemple), un objet intermédiaire StudentsGroups existe. Plusieurs classes peuvent également être ajoutées à un même cours (en Système embarqué par exemple, les SRD et les TI avaient parfois cours ensemble), et c'est ce à quoi sert CoursesStudentGroups.



Logiciel utilisé
Celle-ci est réalisée à partir de ChartDB (https://chart-db.lebonnec.uk). Le site n'enregistre pas le schéma pour tous les utilisateurs dans le stockage du serveur, mais en garde une copie dans les cookies du navigateur. Pour l'exporter, cliquer sur Sauvegarde > Exporter le diagramme. Vous pouvez mettre la dernière version ici, pour que tout le monde puisse la voir :

ChartDB(Sémaphore).json


Si vous souhaitez utiliser un autre logiciel pour prototyper la BDD, libre à vous.



Il n'y a pas de consigne spécifique en ce qui concerne la BDD, vous pouvez la modifier comme bon vous semble.






API
l'API est prototypé sur Swagger (https://swagger-editor.lebonnec.uk/), et visible sur https://swagger-ui.lebonnec.uk/. Vous pouvez la modifier comme bon vous semble.






Séparation des pouvoirs
On distingue 3 types d'utilisateurs sur le service :

Les étudiants

Les enseignants

Les membres de l'administration



Méthodes d'authentification
La méthode utilisée jusque là était d'échanger un JWT. Vous pouvez changer cette méthode comme vous le souhaitez.
Pour les étudiants en revanche, des restrictions supplémentaires doivent être mises en place, pour éviter qu'un étudiant présent ne se connecte avec le compte d'un ami sur son appareil, et valide sa présence pour lui. Pour cela, un identifiant unique sera généré lors de la connexion de l'étudiant à son compte sur son appareil. Il est ensuite envoyé au serveur, et associé à son compte. Cet identifiant est également enregistré dans l'enclave sécurisée du téléphone, et résiste à la désinstallation de l'application (iOS comme Android). Cet identifiant servira ensuite de clef pour signer les requêtes importantes, comme celles de validation de la présence. Le serveur n'autorisera un changement d'appareil qu'une fois par semaine (ou toutes les deux semaines, à voir).









Restrictions d'accès
Tous les utilisateurs ne doivent pas avoir accès à toutes les données, ça va de soit.

Les membres de l'administration ont le droit de tout voir

Les enseignants ont le droit d'accéder aux données relatives à leurs cours et à leurs étudiants

Les étudiants ont le droit d'accéder aux données relatives à leurs cours et à leurs enseignants
Il faudra donc implémenter des restrictions






Fonctionnalités
$




Intéractions


Voici une liste de toutes les actions que doivent pouvoir réaliser les différents types d'utilisateurs avec la première version, depuis les interfaces web et / ou mobiles vers le serveur.



Administration

Se connecter

Ajouter / supprimer un administrateur

Ajouter / supprimer / modifier un étudiant et un enseignant

Ajouter / supprimer / modifier un cours

Ajouter / supprimer un étudiant ou un enseignant d'un cours

Associer une salle à un cours

Voir la liste des présences sur ce cours

Modifier les préférences de l'école (définies dans l'objet SchoolPreferences de la base de données du serveur)



Enseignants

Se connecter

Consulter la liste de ses cours

Consulter les présences sur ses cours

Valider sa présence à son cours (oui l'enseignant doit le faire pour que l'accueil sache que le cours à bien commencer, et pour que les étudiants puissent commencer à signer)

Mettre un étudiant présent / absent manuellement

Ouvrir / fermer la signature pour tous les étudiants (s'il estime qu'il ne veut plus que les étudiants signent par la balise parce qu'il est trop tard par exemple, il peut fermer la signature)

Être notifiés du début d'un cours



Étudiants

Se connecter

Enregistrer un appareil

Obtenir la liste de leurs cours

Valider leur présence en cours

Être notifié de l'ouverture de la signature (quand l'enseignant valide sa présence), et de la nécessité de signer


