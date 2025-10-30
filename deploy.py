#!/usr/bin/env python3
"""
Deployment script for the Phishing Detector Bot
Supports both local and AWS Lambda deployment
"""

import os
import sys
import subprocess
import zipfile
import boto3
from pathlib import Path

def create_deployment_package():
    """Create deployment package for AWS Lambda"""
    print("Creating deployment package...")
    
    # Create package directory
    package_dir = Path("./package")
    package_dir.mkdir(exist_ok=True)
    
    # Install dependencies
    print("Installing dependencies...")
    subprocess.run([
        sys.executable, "-m", "pip", "install", 
        "-r", "requirements.txt", 
        "-t", str(package_dir)
    ], check=True)
    
    # Copy source files
    source_files = [
        "bot.py", "url_analyzer.py", "domain_checker.py", 
        "api_clients.py", "database.py", "config.py", 
        "lambda_handler.py"
    ]
    
    for file in source_files:
        if Path(file).exists():
            subprocess.run(["cp", file, str(package_dir)], check=True)
    
    # Create zip file
    zip_path = Path("./deployment.zip")
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(package_dir)
                zipf.write(file_path, arcname)
    
    print(f"Deployment package created: {zip_path}")
    return zip_path

def deploy_to_lambda(zip_path, function_name="phishing-detector-bot"):
    """Deploy to AWS Lambda"""
    print(f"Deploying to Lambda function: {function_name}")
    
    # Initialize Lambda client
    lambda_client = boto3.client('lambda')
    
    try:
        # Update function code
        with open(zip_path, 'rb') as zip_file:
            lambda_client.update_function_code(
                FunctionName=function_name,
                ZipFile=zip_file.read()
            )
        
        print("Lambda function updated successfully!")
        
        # Update environment variables
        env_vars = {}
        if os.getenv('TELEGRAM_BOT_TOKEN'):
            env_vars['TELEGRAM_BOT_TOKEN'] = os.getenv('TELEGRAM_BOT_TOKEN')
        if os.getenv('VIRUSTOTAL_API_KEY'):
            env_vars['VIRUSTOTAL_API_KEY'] = os.getenv('VIRUSTOTAL_API_KEY')
        if os.getenv('GOOGLE_SAFE_BROWSING_API_KEY'):
            env_vars['GOOGLE_SAFE_BROWSING_API_KEY'] = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
        
        if env_vars:
            lambda_client.update_function_configuration(
                FunctionName=function_name,
                Environment={'Variables': env_vars}
            )
            print("Environment variables updated!")
        
    except lambda_client.exceptions.ResourceNotFoundException:
        print(f"Lambda function {function_name} not found. Creating new function...")
        
        # Create new function
        with open(zip_path, 'rb') as zip_file:
            lambda_client.create_function(
                FunctionName=function_name,
                Runtime='python3.11',
                Role=f'arn:aws:iam::{boto3.client("sts").get_caller_identity()["Account"]}:role/lambda-execution-role',
                Handler='lambda_handler.lambda_handler',
                Code={'ZipFile': zip_file.read()},
                Description='Telegram bot for phishing link detection',
                Timeout=30,
                MemorySize=256,
                Environment={'Variables': env_vars} if env_vars else {}
            )
        
        print("Lambda function created successfully!")

def setup_webhook(bot_token, lambda_function_url):
    """Setup Telegram webhook"""
    import requests
    
    webhook_url = f"https://api.telegram.org/bot{bot_token}/setWebhook"
    
    response = requests.post(webhook_url, json={
        'url': lambda_function_url,
        'allowed_updates': ['message', 'callback_query']
    })
    
    if response.status_code == 200:
        print("Webhook configured successfully!")
    else:
        print(f"Failed to configure webhook: {response.text}")

def main():
    """Main deployment function"""
    if len(sys.argv) < 2:
        print("Usage: python deploy.py [local|lambda]")
        sys.exit(1)
    
    deployment_type = sys.argv[1].lower()
    
    if deployment_type == "local":
        print("Starting local deployment...")
        subprocess.run([sys.executable, "bot.py"])
    
    elif deployment_type == "lambda":
        print("Starting AWS Lambda deployment...")
        
        # Create deployment package
        zip_path = create_deployment_package()
        
        # Deploy to Lambda
        function_name = input("Enter Lambda function name (default: phishing-detector-bot): ").strip()
        if not function_name:
            function_name = "phishing-detector-bot"
        
        deploy_to_lambda(zip_path, function_name)
        
        # Setup webhook (optional)
        setup_webhook_choice = input("Setup Telegram webhook? (y/n): ").strip().lower()
        if setup_webhook_choice == 'y':
            lambda_url = input("Enter Lambda function URL: ").strip()
            bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
            if bot_token and lambda_url:
                setup_webhook(bot_token, lambda_url)
            else:
                print("Bot token or Lambda URL missing!")
        
        # Cleanup
        os.remove(zip_path)
        subprocess.run(["rm", "-rf", "./package"])
        
        print("Deployment completed!")
    
    else:
        print("Invalid deployment type. Use 'local' or 'lambda'")
        sys.exit(1)

if __name__ == "__main__":
    main()