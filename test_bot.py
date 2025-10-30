#!/usr/bin/env python3
"""
Test script for the Phishing Detector Bot
Tests various URL analysis scenarios
"""

from url_analyzer import URLAnalyzer
from domain_checker import DomainChecker
import json

def test_url_analysis():
    """Test URL analysis with various scenarios"""
    analyzer = URLAnalyzer()
    
    test_cases = [
        # Legitimate URLs
        {
            'url': 'https://meet.google.com/abc-defg-hij',
            'expected': 'SAFE',
            'description': 'Legitimate Google Meet link'
        },
        {
            'url': 'https://zoom.us/j/1234567890',
            'expected': 'SAFE',
            'description': 'Legitimate Zoom link'
        },
        {
            'url': 'https://teams.microsoft.com/l/meetup-join/19%3ameeting',
            'expected': 'SAFE',
            'description': 'Legitimate Teams link'
        },
        
        # Suspicious URLs
        {
            'url': 'https://gmeeting.org/abc-defg-hij',
            'expected': 'DANGEROUS',
            'description': 'Typosquatting Google Meet'
        },
        {
            'url': 'https://zo0m.us/j/1234567890',
            'expected': 'DANGEROUS',
            'description': 'Typosquatting Zoom'
        },
        {
            'url': 'https://teams-microsoft.com/meeting',
            'expected': 'SUSPICIOUS',
            'description': 'Suspicious Teams-like domain'
        },
        
        # Malicious patterns
        {
            'url': 'https://bit.ly/urgent-meeting',
            'expected': 'SUSPICIOUS',
            'description': 'URL shortener with suspicious keywords'
        },
        {
            'url': 'https://meet.google.com.phishing.tk/meeting',
            'expected': 'DANGEROUS',
            'description': 'Subdomain spoofing with suspicious TLD'
        }
    ]
    
    print("🧪 Testing URL Analysis")
    print("=" * 50)
    
    passed = 0
    total = len(test_cases)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test_case['description']}")
        print(f"URL: {test_case['url']}")
        
        try:
            result = analyzer.analyze_url(test_case['url'])
            
            if 'error' in result:
                print(f"❌ Error: {result['error']}")
                continue
            
            security_level = result.get('security_level', 'UNKNOWN')
            confidence = result.get('confidence', 0)
            issues = result.get('issues', [])
            
            print(f"Result: {security_level} (Confidence: {confidence:.0f}%)")
            
            if issues:
                print("Issues found:")
                for issue in issues[:3]:
                    print(f"  - {issue}")
            
            # Check if result matches expectation
            if security_level == test_case['expected']:
                print("✅ PASSED")
                passed += 1
            else:
                print(f"❌ FAILED (Expected: {test_case['expected']}, Got: {security_level})")
        
        except Exception as e:
            print(f"❌ Exception: {str(e)}")
    
    print(f"\n📊 Test Results: {passed}/{total} passed ({passed/total*100:.1f}%)")

def test_domain_checker():
    """Test domain checking functionality"""
    checker = DomainChecker()
    
    print("\n🔍 Testing Domain Checker")
    print("=" * 50)
    
    test_domains = [
        'meet.google.com',
        'gmeeting.org',
        'zoom.us',
        'zo0m.us',
        'teams.microsoft.com'
    ]
    
    for domain in test_domains:
        print(f"\nTesting: {domain}")
        
        try:
            result = checker.check_domain(f"https://{domain}")
            
            if 'error' in result:
                print(f"Error: {result['error']}")
                continue
            
            print(f"Legitimate: {result.get('is_legitimate', False)}")
            print(f"Typosquatting Score: {result.get('typosquatting_score', 0):.1f}")
            print(f"SSL Valid: {result.get('ssl_valid', False)}")
            
            if result.get('issues'):
                print("Issues:")
                for issue in result['issues']:
                    print(f"  - {issue}")
        
        except Exception as e:
            print(f"Exception: {str(e)}")

def test_url_extraction():
    """Test URL extraction from text"""
    analyzer = URLAnalyzer()
    
    print("\n📝 Testing URL Extraction")
    print("=" * 50)
    
    test_texts = [
        "Check this meeting link: https://meet.google.com/abc-defg-hij",
        "Suspicious link: gmeeting.org/meeting and also https://zo0m.us/j/123",
        "Multiple links: https://zoom.us/j/123 and https://teams.microsoft.com/meeting",
        "No links in this text",
        "Domain without protocol: meet.google.com/test"
    ]
    
    for i, text in enumerate(test_texts, 1):
        print(f"\nTest {i}: {text}")
        urls = analyzer.extract_urls(text)
        print(f"Extracted URLs: {urls}")

def main():
    """Run all tests"""
    print("🚀 Starting Phishing Detector Bot Tests")
    print("=" * 60)
    
    try:
        test_url_extraction()
        test_domain_checker()
        test_url_analysis()
        
        print("\n✅ All tests completed!")
        
    except KeyboardInterrupt:
        print("\n⚠️ Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Test suite failed: {str(e)}")

if __name__ == "__main__":
    main()