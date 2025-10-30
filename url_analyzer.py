import re
import validators
from urllib.parse import urlparse
from domain_checker import DomainChecker
from api_clients import SecurityAPIClient
from config import SUSPICIOUS_KEYWORDS

class URLAnalyzer:
    def __init__(self):
        self.domain_checker = DomainChecker()
        self.security_client = SecurityAPIClient()
    
    def extract_urls(self, text):
        """Extract URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        
        # Also check for URLs without protocol
        domain_pattern = r'(?:www\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}'
        potential_urls = re.findall(domain_pattern, text)
        
        # Add http:// to potential URLs and validate
        for potential_url in potential_urls:
            full_url = f"http://{potential_url}"
            if validators.url(full_url) and full_url not in urls:
                urls.append(full_url)
        
        return urls
    
    def analyze_url(self, url):
        """Comprehensive URL analysis"""
        if not validators.url(url):
            return {'error': 'Invalid URL format'}
        
        try:
            # Parse URL
            parsed = urlparse(url)
            
            # Initialize analysis results
            analysis = {
                'url': url,
                'domain': parsed.netloc.lower(),
                'path': parsed.path,
                'query': parsed.query,
                'security_level': 'SAFE',  # SAFE, SUSPICIOUS, DANGEROUS
                'confidence': 0,
                'issues': [],
                'recommendations': []
            }
            
            # Domain analysis
            domain_results = self.domain_checker.check_domain(url)
            if 'error' not in domain_results:
                analysis['domain_analysis'] = domain_results
                analysis['issues'].extend(domain_results['issues'])
            
            # Security API checks
            security_results = self.security_client.comprehensive_check(url)
            analysis['security_analysis'] = security_results
            
            # URL structure analysis
            structure_issues = self._analyze_url_structure(url)
            analysis['issues'].extend(structure_issues)
            
            # Content analysis
            content_issues = self._analyze_url_content(url)
            analysis['issues'].extend(content_issues)
            
            # Calculate final security assessment
            analysis = self._calculate_final_assessment(analysis)
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_url_structure(self, url):
        """Analyze URL structure for suspicious patterns"""
        issues = []
        parsed = urlparse(url)
        
        # Check for excessive subdomains
        domain_parts = parsed.netloc.split('.')
        if len(domain_parts) > 4:
            issues.append("Excessive subdomains detected")
        
        # Check for suspicious path patterns
        if '/redirect' in parsed.path or '/r/' in parsed.path:
            issues.append("Contains redirect patterns")
        
        # Check for URL shorteners (basic detection)
        shortener_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
        if any(shortener in parsed.netloc for shortener in shortener_domains):
            issues.append("Uses URL shortener service")
        
        # Check for suspicious query parameters
        if 'token' in parsed.query or 'auth' in parsed.query:
            issues.append("Contains authentication tokens in URL")
        
        return issues
    
    def _analyze_url_content(self, url):
        """Analyze URL content for suspicious keywords"""
        issues = []
        url_lower = url.lower()
        
        found_keywords = [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in url_lower]
        if found_keywords:
            issues.append(f"Contains suspicious keywords: {', '.join(found_keywords)}")
        
        return issues
    
    def _calculate_final_assessment(self, analysis):
        """Calculate final security assessment"""
        risk_score = 0
        
        # Domain analysis scoring
        domain_analysis = analysis.get('domain_analysis', {})
        if not domain_analysis.get('is_legitimate', True):
            risk_score += 40
        
        if domain_analysis.get('typosquatting_score', 0) > 0:
            risk_score += min(domain_analysis['typosquatting_score'], 30)
        
        if domain_analysis.get('domain_age_days') is not None:
            if domain_analysis['domain_age_days'] < 7:
                risk_score += 30
            elif domain_analysis['domain_age_days'] < 30:
                risk_score += 15
        
        if not domain_analysis.get('ssl_valid', True):
            risk_score += 20
        
        if domain_analysis.get('suspicious_tld', False):
            risk_score += 15
        
        # Security API scoring
        security_analysis = analysis.get('security_analysis', {})
        security_score = security_analysis.get('security_score', 100)
        risk_score += (100 - security_score)
        
        # Structure and content issues
        risk_score += len(analysis['issues']) * 5
        
        # Determine security level
        if risk_score >= 70:
            analysis['security_level'] = 'DANGEROUS'
            analysis['confidence'] = min(95, 70 + (risk_score - 70) * 0.5)
        elif risk_score >= 30:
            analysis['security_level'] = 'SUSPICIOUS'
            analysis['confidence'] = min(85, 50 + (risk_score - 30) * 0.875)
        else:
            analysis['security_level'] = 'SAFE'
            analysis['confidence'] = max(60, 100 - risk_score * 2)
        
        # Add recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _generate_recommendations(self, analysis):
        """Generate security recommendations"""
        recommendations = []
        
        if analysis['security_level'] == 'DANGEROUS':
            recommendations.append("🚨 DO NOT CLICK this link")
            recommendations.append("Report this link as phishing")
            recommendations.append("Delete the message containing this link")
        
        elif analysis['security_level'] == 'SUSPICIOUS':
            recommendations.append("⚠️ Exercise extreme caution")
            recommendations.append("Verify the sender's identity")
            recommendations.append("Check the legitimate website directly")
        
        else:
            recommendations.append("✅ Link appears safe")
            recommendations.append("Always verify meeting invitations through official channels")
        
        # Add specific recommendations based on domain type
        domain_analysis = analysis.get('domain_analysis', {})
        if not domain_analysis.get('is_legitimate', True):
            legitimate_examples = self._get_legitimate_examples(analysis['domain'])
            if legitimate_examples:
                recommendations.append(f"Legitimate links look like: {legitimate_examples}")
        
        return recommendations
    
    def _get_legitimate_examples(self, suspicious_domain):
        """Get examples of legitimate domains"""
        if 'meet' in suspicious_domain or 'google' in suspicious_domain:
            return "https://meet.google.com/abc-defg-hij"
        elif 'zoom' in suspicious_domain:
            return "https://zoom.us/j/1234567890"
        elif 'teams' in suspicious_domain or 'microsoft' in suspicious_domain:
            return "https://teams.microsoft.com/l/meetup-join/..."
        
        return None