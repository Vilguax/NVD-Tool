import nvdlib as nvd
from config import CVE_ID
import re

cve = nvd.searchCVE(cveId=CVE_ID)[0]

configurations = []
for i, config in enumerate(cve.configurations):

    conf = config.nodes

    txt = ', '.join(str(x) for x in conf)

    for match in re.finditer(r'cpe:2.3:', txt):
        cpe = txt[match.start():].split()[0][:-2].split(":")
        cpe_parsed = ":".join(cpe[:3] + cpe[4:6] + ["*", "*", "*", "*", "*", "*"])
        configurations.append((cpe_parsed, i+1))

print(configurations)
