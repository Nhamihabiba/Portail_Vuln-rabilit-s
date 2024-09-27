import json
import sys

def get_vulnerability_details(cve_id):
    details = {
        'cve_id': cve_id,
        'published': '2013-03-07',
        'base_score': 'N/A',
        'vector': 'N/A',
        'description': 'The default configuration of OpenSSH through 6.1 enforces a fixed time limit between establishing a TCP connection and completing a login...',
        'epss_score': '7.87%',
        'rank': '585',
        'reports': '10',
        'severity': 'Unknown: 6 / None: 0 / Low: 3 / Medium: 0 / High: 1 / Critical: 0',
        'patching_priority': 'D',
        'reference': [
            'http://www.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/servconf.c?r1=1.234#rev1.234'
        ]
    }
    return details

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sploitscan.py <CVE-ID>")
        sys.exit(1)

    cve_id = sys.argv[1]
    vulnerability_details = get_vulnerability_details(cve_id)
    print(json.dumps(vulnerability_details))
