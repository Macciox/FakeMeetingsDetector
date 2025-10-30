import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from url_analyzer import URLAnalyzer
from database import cache
from config import TELEGRAM_BOT_TOKEN

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class PhishingDetectorBot:
    def __init__(self):
        self.analyzer = URLAnalyzer()
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        welcome_message = """
👋 **Welcome to Phishing Link Detector Bot!**

I help you identify dangerous links before you click them, especially fake meeting invitations.

**How to use:**
• Send me any message with links and I'll analyze them
• Use /check <url> to check a specific link
• Forward suspicious messages to me

**Commands:**
/start - Show this message
/check <url> - Check a specific URL
/help - Show detailed help
/stats - Show bot statistics

🔒 **Stay safe online!**
        """
        
        await update.message.reply_text(welcome_message, parse_mode='Markdown')
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        help_message = """
🛡️ **Phishing Link Detector - Help**

**What I check:**
✅ Domain legitimacy (Google Meet, Zoom, Teams, etc.)
✅ Typosquatting detection
✅ Domain age and SSL certificates
✅ Security reputation via VirusTotal
✅ Suspicious URL patterns

**Security Levels:**
🟢 **SAFE** - Link appears legitimate
🟡 **SUSPICIOUS** - Exercise caution
🔴 **DANGEROUS** - Do not click!

**Examples of legitimate links:**
• Google Meet: https://meet.google.com/abc-defg-hij
• Zoom: https://zoom.us/j/1234567890
• Teams: https://teams.microsoft.com/l/meetup-join/...

**Red flags:**
❌ gmeeting.org (fake Google)
❌ zo0m.us (typosquatting)
❌ Newly registered domains
❌ No SSL certificate
❌ Flagged by security services

**Tips:**
• Always verify meeting invitations through official channels
• Check the sender's identity
• When in doubt, don't click!
        """
        
        await update.message.reply_text(help_message, parse_mode='Markdown')
    
    async def stats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /stats command"""
        stats = cache.get_stats()
        
        stats_message = f"""
📊 **Bot Statistics**

🔍 Total links checked: {stats['total_checks']}
🚨 Threats detected: {stats['threats_found']}
⚡ Cache hits: {stats['cache_hits']}

Detection rate: {(stats['threats_found'] / max(stats['total_checks'], 1) * 100):.1f}%
        """
        
        await update.message.reply_text(stats_message, parse_mode='Markdown')
    
    async def check_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /check command"""
        if not context.args:
            await update.message.reply_text(
                "Please provide a URL to check.\nExample: /check https://example.com"
            )
            return
        
        url = ' '.join(context.args)
        await self._analyze_and_respond(update, [url])
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle regular messages with potential URLs"""
        user_id = update.effective_user.id
        
        # Check rate limiting
        if not cache.check_rate_limit(user_id):
            await update.message.reply_text(
                "⚠️ Rate limit exceeded. Please wait before sending more requests."
            )
            return
        
        # Extract URLs from message
        urls = self.analyzer.extract_urls(update.message.text)
        
        if not urls:
            await update.message.reply_text(
                "No URLs found in your message. Send me a link to analyze!"
            )
            return
        
        await self._analyze_and_respond(update, urls)
    
    async def _analyze_and_respond(self, update: Update, urls):
        """Analyze URLs and send response"""
        if len(urls) > 5:
            await update.message.reply_text(
                "⚠️ Too many URLs in one message. Please send up to 5 URLs at a time."
            )
            return
        
        # Send "analyzing" message
        analyzing_msg = await update.message.reply_text("🔍 Analyzing link(s)...")
        
        responses = []
        
        for url in urls:
            # Check cache first
            cached_result = cache.get_cached_result(url)
            
            if cached_result:
                analysis = cached_result
            else:
                # Perform analysis
                analysis = self.analyzer.analyze_url(url)
                
                if 'error' not in analysis:
                    cache.cache_result(url, analysis)
            
            # Generate response
            response = self._format_analysis_response(analysis)
            responses.append(response)
        
        # Delete analyzing message
        await analyzing_msg.delete()
        
        # Send results
        full_response = '\n\n' + '='*50 + '\n\n'.join(responses)
        
        # Split long messages
        if len(full_response) > 4000:
            for response in responses:
                await update.message.reply_text(response, parse_mode='Markdown')
        else:
            await update.message.reply_text(full_response, parse_mode='Markdown')
    
    def _format_analysis_response(self, analysis):
        """Format analysis results into user-friendly message"""
        if 'error' in analysis:
            return f"❌ Error analyzing URL: {analysis['error']}"
        
        url = analysis['url']
        security_level = analysis['security_level']
        confidence = analysis.get('confidence', 0)
        issues = analysis.get('issues', [])
        recommendations = analysis.get('recommendations', [])
        
        # Security level emoji and message
        if security_level == 'DANGEROUS':
            level_emoji = "🔴"
            level_text = "**DANGEROUS LINK - DO NOT CLICK**"
        elif security_level == 'SUSPICIOUS':
            level_emoji = "🟡"
            level_text = "**SUSPICIOUS LINK - EXERCISE CAUTION**"
        else:
            level_emoji = "🟢"
            level_text = "**SAFE LINK**"
        
        # Build response
        response = f"{level_emoji} {level_text}\n\n"
        response += f"🔗 **URL:** `{url}`\n"
        response += f"📊 **Confidence:** {confidence:.0f}%\n\n"
        
        # Add issues if any
        if issues:
            response += "⚠️ **Issues found:**\n"
            for issue in issues[:5]:  # Limit to 5 issues
                response += f"❌ {issue}\n"
            
            if len(issues) > 5:
                response += f"... and {len(issues) - 5} more issues\n"
            response += "\n"
        
        # Add recommendations
        if recommendations:
            response += "💡 **Recommendations:**\n"
            for rec in recommendations[:3]:  # Limit to 3 recommendations
                response += f"• {rec}\n"
        
        # Add domain analysis details for dangerous/suspicious links
        if security_level in ['DANGEROUS', 'SUSPICIOUS']:
            domain_analysis = analysis.get('domain_analysis', {})
            if domain_analysis.get('domain_age_days') is not None:
                response += f"\n📅 Domain age: {domain_analysis['domain_age_days']} days"
            
            # Add VirusTotal results if available
            security_analysis = analysis.get('security_analysis', {})
            vt_results = security_analysis.get('api_results', {}).get('virustotal', {})
            if 'positives' in vt_results and 'total' in vt_results:
                response += f"\n🛡️ VirusTotal: {vt_results['positives']}/{vt_results['total']} vendors flagged"
        
        return response
    
    async def error_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle errors"""
        logger.error(f"Update {update} caused error {context.error}")
        
        if update and update.message:
            await update.message.reply_text(
                "❌ An error occurred while processing your request. Please try again."
            )

def main():
    """Start the bot"""
    # Create application
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Create bot instance
    bot = PhishingDetectorBot()
    
    # Add handlers
    application.add_handler(CommandHandler("start", bot.start_command))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(CommandHandler("stats", bot.stats_command))
    application.add_handler(CommandHandler("check", bot.check_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
    
    # Add error handler
    application.add_error_handler(bot.error_handler)
    
    # Start bot
    logger.info("Starting Phishing Detector Bot...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()