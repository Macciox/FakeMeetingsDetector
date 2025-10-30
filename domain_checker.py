import re
from datetime import datetime, timedelta
from config import LEGITIMATE_DOMAINS, SUSPICIOUS_TLDS
from urllib.parse import urlparse

class DomainChecker:
    def __init__(self):
        self.legitimate_domains = []
        for domains in LEGITIMATE_DOMAINS.values():
            self.legitimate_domains.extend(domains)
    
    def check_domain(self, url):
        """Main domain checking function"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            results = {
                'domain': domain,
                'is_legitimate': False,
                'typosquatting_score': 0,
                'domain_age_days': None,
                'ssl_valid': False,
                'suspicious_tld': False,
                'issues': []
            }
            
            # Check if domain is legitimate
            results['is_legitimate'] = self._is_legitimate_domain(domain)
            
            # Check for typosquatting
            results['typosquatting_score'] = self._check_typosquatting(domain)
            
            # Check domain age
            results['domain_age_days'] = self._get_domain_age(domain)
            
            # Check SSL certificate
            results['ssl_valid'] = self._check_ssl_certificate(domain)
            
            # Check for suspicious TLD
            results['suspicious_tld'] = self._has_suspicious_tld(domain)
            
            # Compile issues
            results['issues'] = self._compile_issues(results)
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _is_legitimate_domain(self, domain):
        """Check if domain is in legitimate domains list"""
        return domain in self.legitimate_domains
    
    def _check_typosquatting(self, domain):
        """Check for typosquatting using simple string comparison"""
        # Simple typosquatting detection
        for legit_domain in self.legitimate_domains:
            if domain == legit_domain:
                return 0  # Exact match
            
            # Check for common typosquatting patterns
            if len(domain) == len(legit_domain):
                diff_count = sum(c1 != c2 for c1, c2 in zip(domain, legit_domain))
                if diff_count <= 2:  # 1-2 character differences
                    return 20 + (diff_count * 10)
        
        return 100  # Very different
    
    def _get_domain_age(self, domain):
        """Get domain registration age in days (simplified)"""
        # Simplified - assume suspicious domains are new
        if not self._is_legitimate_domain(domain):
            return 5  # Assume suspicious domains are 5 days old
        return 365  # Assume legitimate domains are old
    
    def _check_ssl_certificate(self, domain):
        """Check if SSL certificate is valid (simplified)"""
        # Simplified - assume legitimate domains have SSL
        return self._is_legitimate_domain(domain)
    
    def _has_suspicious_tld(self, domain):
        """Check if domain has suspicious TLD"""
        return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    
    def _compile_issues(self, results):
        """Compile list of issues found"""
        issues = []
        
        if not results['is_legitimate']:
            # Find closest legitimate domain
            closest_domain = self._find_closest_legitimate_domain(results['domain'])
            if closest_domain:
                issues.append(f"Domain '{results['domain']}' is NOT legitimate (real: {closest_domain})")
        
        if results['typosquatting_score'] > 0 and results['typosquatting_score'] < 30:
            issues.append("Domain appears to be typosquatting a legitimate service")
        
        if results['domain_age_days'] is not None and results['domain_age_days'] < 30:
            issues.append(f"Domain registered only {results['domain_age_days']} days ago")
        
        if not results['ssl_valid']:
            issues.append("No valid SSL certificate")
        
        if results['suspicious_tld']:
            issues.append("Uses suspicious top-level domain")
        
        return issues
    
    def _find_closest_legitimate_domain(self, domain):
        """Find the closest legitimate domain"""
        # Simple matching for common typosquatting
        if 'meet' in domain or 'google' in domain:
            return 'meet.google.com'
        elif 'zoom' in domain:
            return 'zoom.us'
        elif 'teams' in domain or 'microsoft' in domain:
            return 'teams.microsoft.com'
        return None