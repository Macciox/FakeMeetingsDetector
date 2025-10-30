import requests
import json
import base64
from config import VIRUSTOTAL_API_KEY, GOOGLE_SAFE_BROWSING_API_KEY

class VirusTotalClient:
    def __init__(self):
        self.api_key = VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/vtapi/v2"
    
    def check_url(self, url):
        """Check URL reputation via VirusTotal"""
        if not self.api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        try:
            # Submit URL for scanning
            params = {
                'apikey': self.api_key,
                'url': url
            }
            
            response = requests.post(f"{self.base_url}/url/scan", data=params)
            
            if response.status_code == 200:
                scan_result = response.json()
                resource = scan_result.get('resource')
                
                # Get scan report
                report_params = {
                    'apikey': self.api_key,
                    'resource': resource
                }
                
                report_response = requests.get(f"{self.base_url}/url/report", params=report_params)
                
                if report_response.status_code == 200:
                    report = report_response.json()
                    
                    return {
                        'positives': report.get('positives', 0),
                        'total': report.get('total', 0),
                        'scan_date': report.get('scan_date'),
                        'permalink': report.get('permalink')
                    }
            
            return {'error': 'Failed to get VirusTotal report'}
            
        except Exception as e:
            return {'error': str(e)}

class GoogleSafeBrowsingClient:
    def __init__(self):
        self.api_key = GOOGLE_SAFE_BROWSING_API_KEY
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    def check_url(self, url):
        """Check URL via Google Safe Browsing API"""
        if not self.api_key:
            return {'error': 'Google Safe Browsing API key not configured'}
        
        try:
            payload = {
                "client": {
                    "clientId": "telegram-phishing-bot",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(
                f"{self.base_url}?key={self.api_key}",
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                matches = result.get('matches', [])
                
                return {
                    'is_safe': len(matches) == 0,
                    'threats': [match.get('threatType') for match in matches]
                }
            
            return {'error': 'Failed to check Google Safe Browsing'}
            
        except Exception as e:
            return {'error': str(e)}

class SecurityAPIClient:
    def __init__(self):
        self.virustotal = VirusTotalClient()
        self.safe_browsing = GoogleSafeBrowsingClient()
    
    def comprehensive_check(self, url):
        """Perform comprehensive security check using multiple APIs"""
        results = {
            'virustotal': self.virustotal.check_url(url),
            'safe_browsing': self.safe_browsing.check_url(url)
        }
        
        # Compile overall security assessment
        security_score = self._calculate_security_score(results)
        
        return {
            'security_score': security_score,
            'api_results': results
        }
    
    def _calculate_security_score(self, results):
        """Calculate overall security score (0-100, where 100 is safest)"""
        score = 100
        
        # VirusTotal assessment
        vt_result = results.get('virustotal', {})
        if 'positives' in vt_result and 'total' in vt_result:
            positives = vt_result['positives']
            total = vt_result['total']
            
            if total > 0:
                vt_ratio = positives / total
                score -= (vt_ratio * 50)  # Reduce score based on detection ratio
        
        # Google Safe Browsing assessment
        sb_result = results.get('safe_browsing', {})
        if not sb_result.get('is_safe', True):
            score -= 40  # Significant penalty for Safe Browsing detection
        
        return max(0, int(score))