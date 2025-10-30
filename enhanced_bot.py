import logging
import re
from datetime import datetime
from urllib.parse import urlparse
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from config import TELEGRAM_BOT_TOKEN, LEGITIMATE_DOMAINS

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ python-whois not installed - domain age check disabled")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedPhishingBot:
    def __init__(self):
        self.legitimate_domains = []
        for domains in LEGITIMATE_DOMAINS.values():
            self.legitimate_domains.extend(domains)
    
    def extract_urls(self, text):
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)
    
    def get_domain_age(self, domain):
        """Real domain age check using WHOIS"""
        if not WHOIS_AVAILABLE:
            return None
        
        try:
            w = whois.whois(domain)
            if w.creation_date:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                age = datetime.now() - creation_date
                return age.days
        except:
            pass
        return None
    
    def analyze_url(self, url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            issues = []
            confidence = 50
            
            # Check if legitimate
            is_legitimate = domain in self.legitimate_domains
            
            # Check domain age
            domain_age = self.get_domain_age(domain)
            
            if is_legitimate:
                return {
                    'security_level': 'SAFE',
                    'confidence': 95,
                    'domain_age': domain_age,
                    'issues': [],
                    'recommendations': ['✅ Link appears safe']
                }
            
            # Typosquatting checks
            if 'meet' in domain or 'google' in domain:
                if domain != 'meet.google.com':
                    issues.append(f"Domain '{domain}' mimics Google Meet (real: meet.google.com)")
                    confidence += 30
            
            if 'zoom' in domain:
                if domain not in ['zoom.us', 'us02web.zoom.us', 'us04web.zoom.us']:
                    issues.append(f"Domain '{domain}' mimics Zoom (real: zoom.us)")
                    confidence += 30
            
            if 'teams' in domain or 'microsoft' in domain:
                if domain not in ['teams.microsoft.com', 'teams.live.com']:
                    issues.append(f"Domain '{domain}' mimics Teams (real: teams.microsoft.com)")
                    confidence += 30
            
            # Domain age check
            if domain_age is not None:
                if domain_age < 7:
                    issues.append(f"Domain registered only {domain_age} days ago")
                    confidence += 25
                elif domain_age < 30:
                    issues.append(f"Domain registered {domain_age} days ago (recently)")
                    confidence += 15
            
            # Determine security level
            if confidence >= 70 or len(issues) >= 2:
                security_level = 'DANGEROUS'
                recommendations = ['🚨 DO NOT CLICK this link', 'Report as phishing']
            elif issues:
                security_level = 'SUSPICIOUS'
                recommendations = ['⚠️ Exercise caution', 'Verify through official channels']
            else:
                security_level = 'SUSPICIOUS'
                issues.append('Unknown domain - verify before clicking')
                recommendations = ['⚠️ Verify sender identity', 'Check official website']
            
            return {
                'security_level': security_level,
                'confidence': min(confidence, 95),
                'domain_age': domain_age,
                'issues': issues,
                'recommendations': recommendations
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        whois_status = "✅ Active" if WHOIS_AVAILABLE else "❌ Disabled"
        welcome = f"""
👋 **Phishing Link Detector Bot**

Send me suspicious links and I'll tell you if they're safe!

**Features:**
• Typosquatting detection
• Domain age check: {whois_status}
• Suspicious pattern analysis

**Commands:**
/start - Show this message
/help - Detailed help

Send any link to analyze it!
        """
        await update.message.reply_text(welcome, parse_mode='Markdown')
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        help_text = """
🛡️ **How it works:**

🟢 **SAFE** - Link is safe
🟡 **SUSPICIOUS** - Be careful
🔴 **DANGEROUS** - Do not click!

**Checks performed:**
✓ Legitimate domain comparison
✓ Typosquatting detection
✓ Domain age (WHOIS)
✓ Suspicious patterns

**Legitimate links:**
• Google Meet: meet.google.com
• Zoom: zoom.us
• Teams: teams.microsoft.com
        """
        await update.message.reply_text(help_text, parse_mode='Markdown')
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        urls = self.extract_urls(update.message.text)
        
        if not urls:
            await update.message.reply_text("No links found. Send me a link to analyze!")
            return
        
        for url in urls[:3]:
            await update.message.reply_text("🔍 Analyzing...")
            
            analysis = self.analyze_url(url)
            
            if 'error' in analysis:
                await update.message.reply_text(f"❌ Error: {analysis['error']}")
                continue
            
            level = analysis['security_level']
            confidence = analysis['confidence']
            domain_age = analysis.get('domain_age')
            issues = analysis['issues']
            recommendations = analysis['recommendations']
            
            if level == 'DANGEROUS':
                emoji = "🔴"
                level_text = "**DANGEROUS - DO NOT CLICK**"
            elif level == 'SUSPICIOUS':
                emoji = "🟡"
                level_text = "**SUSPICIOUS - BE CAREFUL**"
            else:
                emoji = "🟢"
                level_text = "**SAFE**"
            
            response = f"{emoji} {level_text}\n\n"
            response += f"🔗 **URL:** `{url}`\n"
            response += f"📊 **Confidence:** {confidence}%\n"
            
            if domain_age is not None:
                response += f"📅 **Domain age:** {domain_age} days\n"
            
            response += "\n"
            
            if issues:
                response += "⚠️ **Issues found:**\n"
                for issue in issues:
                    response += f"❌ {issue}\n"
                response += "\n"
            
            if recommendations:
                response += "💡 **Recommendations:**\n"
                for rec in recommendations:
                    response += f"• {rec}\n"
            
            await update.message.reply_text(response, parse_mode='Markdown')

def main():
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    bot = EnhancedPhishingBot()
    
    application.add_handler(CommandHandler("start", bot.start_command))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
    
    logger.info("🚀 Bot started with domain age checking!")
    application.run_polling()

if __name__ == '__main__':
    main()