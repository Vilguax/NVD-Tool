#test.py
#Fichier de test pour l'ajout de fonctionnalités au projet

import datetime

end = datetime.datetime.now()
last4h = end - datetime.timedelta(days=4)

print(end, last4h)

