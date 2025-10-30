# Telegram Phishing Link Detector Bot

A Telegram bot that helps users identify phishing and scam links, particularly focusing on fake video conferencing platform links (Google Meet, Zoom, Microsoft Teams, etc.).

## Features

- **Real-time URL Analysis**: Analyzes links sent by users and provides security assessment
- **Typosquatting Detection**: Identifies domains that mimic legitimate services
- **Domain Verification**: Checks domain age, SSL certificates, and legitimacy
- **Security API Integration**: Uses VirusTotal and Google Safe Browsing APIs
- **Pattern Recognition**: Detects suspicious URL structures and content
- **Rate Limiting**: Prevents abuse with user-based rate limiting
- **Caching**: Improves performance with intelligent result caching

## Security Levels

- 🟢 **SAFE**: Link appears legitimate and safe to click
- 🟡 **SUSPICIOUS**: Exercise caution, verify through official channels
- 🔴 **DANGEROUS**: Do not click, likely phishing attempt

## Installation

### Prerequisites

- Python 3.11 or higher
- Telegram Bot Token (from @BotFather)
- Optional: VirusTotal API key
- Optional: Google Safe Browsing API key

### Local Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd FakeMeetingsDetector
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   ```bash
   copy .env.example .env
   # Edit .env with your API keys
   ```

4. **Run the bot**
   ```bash
   python bot.py
   ```

### Environment Variables

Create a `.env` file with the following variables:

```env
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
VIRUSTOTAL_API_KEY=your_virustotal_api_key (optional)
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_key (optional)
```

## Usage

### Bot Commands

- `/start` - Initialize bot and show welcome message
- `/check <url>` - Check a specific URL for security threats
- `/help` - Show detailed help and usage instructions
- `/stats` - Display bot statistics (links checked, threats found)

### How to Use

1. **Start a chat** with the bot
2. **Send any message** containing URLs or **forward messages** with suspicious links
3. **Get instant analysis** with security assessment and recommendations
4. **Follow recommendations** to stay safe online

### Example Interactions

```
User: https://gmeeting.org/abc-defg-hij

Bot: 🔴 DANGEROUS LINK - DO NOT CLICK

🔗 URL: https://gmeeting.org/abc-defg-hij
📊 Confidence: 95%

⚠️ Issues found:
❌ Domain "gmeeting.org" is NOT Google (real: meet.google.com)
❌ Domain registered 3 days ago
❌ No valid SSL certificate

💡 Recommendations:
• 🚨 DO NOT CLICK this link
• Report this link as phishing
• Legitimate links look like: https://meet.google.com/abc-defg-hij
```

## AWS Deployment

### Lambda Deployment

1. **Create deployment package**
   ```bash
   pip install -r requirements.txt -t ./package
   cp *.py ./package/
   cd package && zip -r ../deployment.zip .
   ```

2. **Create Lambda function**
   - Runtime: Python 3.11
   - Handler: bot.lambda_handler
   - Upload deployment.zip

3. **Configure environment variables** in Lambda console

4. **Set up API Gateway** for webhook (optional)

### EC2 Deployment

1. **Launch EC2 instance** (t3.micro recommended)
2. **Install Python and dependencies**
   ```bash
   sudo yum update -y
   sudo yum install python3 python3-pip -y
   pip3 install -r requirements.txt
   ```

3. **Configure systemd service**
   ```bash
   sudo nano /etc/systemd/system/phishing-bot.service
   ```

4. **Start and enable service**
   ```bash
   sudo systemctl start phishing-bot
   sudo systemctl enable phishing-bot
   ```

## API Keys Setup

### VirusTotal API

1. Register at [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Get your API key from the API section
3. Add to `.env` file: `VIRUSTOTAL_API_KEY=your_key_here`

### Google Safe Browsing API

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Enable Safe Browsing API
3. Create credentials (API key)
4. Add to `.env` file: `GOOGLE_SAFE_BROWSING_API_KEY=your_key_here`

## Security Considerations

- **API Keys**: Store in environment variables or AWS Secrets Manager
- **Rate Limiting**: Implemented to prevent abuse (10 requests/hour per user)
- **Input Validation**: All URLs are validated before processing
- **No Link Following**: Bot never actually visits suspicious links
- **Logging**: All activities are logged for monitoring

## Monitoring and Maintenance

### Logs

The bot logs all activities including:
- User requests and responses
- API calls and results
- Errors and exceptions
- Security assessments

### Statistics

Track bot performance with:
- Total links analyzed
- Threats detected
- Cache hit rate
- API usage

### Updates

Regular updates recommended for:
- New phishing patterns
- Updated legitimate domain lists
- Security improvements
- Bug fixes

## Troubleshooting

### Common Issues

1. **Bot not responding**
   - Check bot token validity
   - Verify network connectivity
   - Check logs for errors

2. **API errors**
   - Verify API keys are correct
   - Check API quotas and limits
   - Ensure APIs are enabled

3. **False positives**
   - Review domain checking logic
   - Update legitimate domain lists
   - Adjust security thresholds

### Support

For issues and questions:
1. Check the logs for error messages
2. Verify configuration settings
3. Test with known safe/unsafe URLs
4. Review API documentation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This bot is a security tool designed to help identify potential phishing links. While it uses multiple detection methods, it may not catch all threats. Users should always exercise caution when clicking links and verify through official channels when in doubt.