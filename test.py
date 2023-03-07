#test.py
#Fichier de test pour l'ajout de fonctionnalités au projet

import nvdlib as nvd

r = nvd.searchCVE(cveId='CVE-2020-1920')[0]

conf = r.configurations

for i in conf:
    print(i)
    
    