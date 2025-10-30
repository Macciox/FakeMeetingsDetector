import logging
import re
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from config import TELEGRAM_BOT_TOKEN, LEGITIMATE_DOMAINS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SimplePhishingBot:
    def __init__(self):
        self.legitimate_domains = []
        for domains in LEGITIMATE_DOMAINS.values():
            self.legitimate_domains.extend(domains)
    
    def extract_urls(self, text):
        """Extract URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)
    
    def analyze_url(self, url):
        """Simple URL analysis"""
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check if legitimate
            if domain in self.legitimate_domains:
                return {
                    'security_level': 'SAFE',
                    'confidence': 95,
                    'issues': [],
                    'recommendations': ['✅ Link appears safe']
                }
            
            # Check for typosquatting patterns
            issues = []
            if 'meet' in domain and 'google' not in domain:
                issues.append(f"Domain '{domain}' mimics Google Meet (real: meet.google.com)")
            elif 'zoom' in domain and domain != 'zoom.us':
                issues.append(f"Domain '{domain}' mimics Zoom (real: zoom.us)")
            elif 'teams' in domain and 'microsoft' not in domain:
                issues.append(f"Domain '{domain}' mimics Teams (real: teams.microsoft.com)")
            
            if issues:
                return {
                    'security_level': 'DANGEROUS',
                    'confidence': 90,
                    'issues': issues,
                    'recommendations': ['🚨 DO NOT CLICK this link', 'Report as phishing']
                }
            
            return {
                'security_level': 'SUSPICIOUS',
                'confidence': 70,
                'issues': ['Unknown domain - verify before clicking'],
                'recommendations': ['⚠️ Exercise caution', 'Verify through official channels']
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        welcome = """
👋 **Phishing Link Detector Bot**

Inviami link sospetti e ti dirò se sono sicuri!

**Comandi:**
/start - Mostra questo messaggio
/help - Aiuto dettagliato

**Come usare:**
Invia qualsiasi messaggio con link e li analizzerò automaticamente.
        """
        await update.message.reply_text(welcome, parse_mode='Markdown')
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        help_text = """
🛡️ **Come funziona:**

🟢 **SAFE** - Link sicuro
🟡 **SUSPICIOUS** - Attenzione
🔴 **DANGEROUS** - Non cliccare!

**Esempi di link legittimi:**
• Google Meet: https://meet.google.com/abc-defg-hij
• Zoom: https://zoom.us/j/1234567890
• Teams: https://teams.microsoft.com/...

**Attenzione a:**
❌ gmeeting.org (falso Google)
❌ zo0m.us (falso Zoom)
❌ Domini sospetti
        """
        await update.message.reply_text(help_text, parse_mode='Markdown')
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle messages with URLs"""
        urls = self.extract_urls(update.message.text)
        
        if not urls:
            await update.message.reply_text("Nessun link trovato. Inviami un link da analizzare!")
            return
        
        for url in urls[:3]:  # Max 3 URLs
            analysis = self.analyze_url(url)
            
            if 'error' in analysis:
                await update.message.reply_text(f"❌ Errore nell'analisi: {analysis['error']}")
                continue
            
            # Format response
            level = analysis['security_level']
            confidence = analysis['confidence']
            issues = analysis['issues']
            recommendations = analysis['recommendations']
            
            if level == 'DANGEROUS':
                emoji = "🔴"
                level_text = "**PERICOLOSO - NON CLICCARE**"
            elif level == 'SUSPICIOUS':
                emoji = "🟡"
                level_text = "**SOSPETTO - ATTENZIONE**"
            else:
                emoji = "🟢"
                level_text = "**SICURO**"
            
            response = f"{emoji} {level_text}\n\n"
            response += f"🔗 **URL:** `{url}`\n"
            response += f"📊 **Confidenza:** {confidence}%\n\n"
            
            if issues:
                response += "⚠️ **Problemi trovati:**\n"
                for issue in issues:
                    response += f"❌ {issue}\n"
                response += "\n"
            
            if recommendations:
                response += "💡 **Raccomandazioni:**\n"
                for rec in recommendations:
                    response += f"• {rec}\n"
            
            await update.message.reply_text(response, parse_mode='Markdown')

def main():
    """Start the bot"""
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    bot = SimplePhishingBot()
    
    application.add_handler(CommandHandler("start", bot.start_command))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
    
    logger.info("🚀 Bot avviato! Pronto per analizzare link...")
    application.run_polling()

if __name__ == '__main__':
    main()