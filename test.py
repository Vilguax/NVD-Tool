#test.py
#Fichier de test pour l'ajout de fonctionnalités au projet

import nvdlib as nvd
import datetime

end = datetime.datetime.now()
last4h = end - datetime.timedelta(days=30)

r = nvd.searchCVE(lastModStartDate=last4h, lastModEndDate=end)
c = 0
for i in r:
    c += 1
    
print('Nombre de CVEs: ', c)