import json

json_response = '[{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:xen:xen:*:*:*:*:*:*:*:*", "versionStartIncluding": "4.9.0", "matchCriteriaId": "49311C62-4662-40C1-9F0D-B366D8C1379F"}]}]}, {"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*", "matchCriteriaId": "FA6FEEC2-9F11-4643-8827-749718254FED"}, {"vulnerable": true, "criteria": "cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*", "matchCriteriaId": "80E516C0-98A4-4ADE-B69F-66A772E2BAAA"}, {"vulnerable": true, "criteria": "cpe:2.3:o:fedoraproject:fedora:36:*:*:*:*:*:*:*", "matchCriteriaId": "5C675112-476C-4D7C-BCB9-A2FB2D0BC9FD"}, {"vulnerable": true, "criteria": "cpe:2.3:o:fedoraproject:fedora:37:*:*:*:*:*:*:*", "matchCriteriaId": "E30D0E6F-4AE8-4284-8716-991DFA48CC5D"}]}]}]'

parsed_json = json.loads(json_response)

for item in parsed_json:
    for node in item['nodes']:
        for cpe_match in node['cpeMatch']:
            print('Criteria:', cpe_match['criteria'])
            if 'versionStartIncluding' in cpe_match:
                print('Version Start Including:', cpe_match['versionStartIncluding'])
            print('Match Criteria ID:', cpe_match['matchCriteriaId'])
            print('Vulnerable:', cpe_match['vulnerable'])
