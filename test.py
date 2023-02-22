import nvdlib as nvd

r = nvd.searchCVE(cveId="CVE-2023-20076")

print(r[0].v30score)