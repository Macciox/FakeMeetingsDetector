import os
from dotenv import load_dotenv

load_dotenv()

# Bot Configuration
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')

# Legitimate domains
LEGITIMATE_DOMAINS = {
    'google_meet': ['meet.google.com'],
    'zoom': ['zoom.us', 'us02web.zoom.us', 'us04web.zoom.us', 'us05web.zoom.us'],
    'microsoft_teams': ['teams.microsoft.com', 'teams.live.com'],
    'webex': ['webex.com'],
    'skype': ['join.skype.com'],
    'discord': ['discord.gg', 'discord.com']
}

# Suspicious patterns
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.stream']
SUSPICIOUS_KEYWORDS = ['urgent', 'verify', 'suspended', 'click', 'now', 'limited', 'expire']

# Rate limiting
MAX_REQUESTS_PER_USER = 10
RATE_LIMIT_WINDOW = 3600  # 1 hour

# Cache settings
CACHE_TTL = 86400  # 24 hours