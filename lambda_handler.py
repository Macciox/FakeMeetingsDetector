import json
import asyncio
from telegram import Update
from telegram.ext import Application
from bot import PhishingDetectorBot
from config import TELEGRAM_BOT_TOKEN

# Global application instance
application = None
bot_instance = None

def lambda_handler(event, context):
    """AWS Lambda handler for Telegram webhook"""
    global application, bot_instance
    
    try:
        # Initialize application if not exists
        if application is None:
            application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
            bot_instance = PhishingDetectorBot()
            
            # Add handlers
            from telegram.ext import CommandHandler, MessageHandler, filters
            application.add_handler(CommandHandler("start", bot_instance.start_command))
            application.add_handler(CommandHandler("help", bot_instance.help_command))
            application.add_handler(CommandHandler("stats", bot_instance.stats_command))
            application.add_handler(CommandHandler("check", bot_instance.check_command))
            application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot_instance.handle_message))
            application.add_error_handler(bot_instance.error_handler)
        
        # Parse webhook data
        body = json.loads(event['body'])
        update = Update.de_json(body, application.bot)
        
        # Process update
        asyncio.run(application.process_update(update))
        
        return {
            'statusCode': 200,
            'body': json.dumps({'status': 'ok'})
        }
        
    except Exception as e:
        print(f"Error processing update: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }