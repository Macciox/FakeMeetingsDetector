import json
import time
from datetime import datetime, timedelta
from config import CACHE_TTL, MAX_REQUESTS_PER_USER, RATE_LIMIT_WINDOW

class SimpleCache:
    """Simple in-memory cache for URL analysis results and rate limiting"""
    
    def __init__(self):
        self.url_cache = {}
        self.user_requests = {}
        self.stats = {
            'total_checks': 0,
            'threats_found': 0,
            'cache_hits': 0
        }
    
    def get_cached_result(self, url):
        """Get cached analysis result for URL"""
        if url in self.url_cache:
            cached_data = self.url_cache[url]
            
            # Check if cache is still valid
            if time.time() - cached_data['timestamp'] < CACHE_TTL:
                self.stats['cache_hits'] += 1
                return cached_data['result']
            else:
                # Remove expired cache entry
                del self.url_cache[url]
        
        return None
    
    def cache_result(self, url, result):
        """Cache analysis result for URL"""
        self.url_cache[url] = {
            'result': result,
            'timestamp': time.time()
        }
        
        # Update stats
        self.stats['total_checks'] += 1
        if result.get('security_level') in ['SUSPICIOUS', 'DANGEROUS']:
            self.stats['threats_found'] += 1
    
    def check_rate_limit(self, user_id):
        """Check if user has exceeded rate limit"""
        current_time = time.time()
        
        if user_id not in self.user_requests:
            self.user_requests[user_id] = []
        
        # Remove old requests outside the window
        self.user_requests[user_id] = [
            req_time for req_time in self.user_requests[user_id]
            if current_time - req_time < RATE_LIMIT_WINDOW
        ]
        
        # Check if user has exceeded limit
        if len(self.user_requests[user_id]) >= MAX_REQUESTS_PER_USER:
            return False
        
        # Add current request
        self.user_requests[user_id].append(current_time)
        return True
    
    def get_stats(self):
        """Get bot statistics"""
        return self.stats.copy()
    
    def add_known_phishing_domain(self, domain, reported_by=None):
        """Add domain to known phishing list"""
        # In a real implementation, this would be stored in a persistent database
        pass
    
    def is_known_phishing_domain(self, domain):
        """Check if domain is in known phishing list"""
        # In a real implementation, this would check against a database
        return False

# Global cache instance
cache = SimpleCache()