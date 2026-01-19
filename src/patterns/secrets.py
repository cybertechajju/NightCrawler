"""
NightCrawler v2.0 - Enhanced Secret Patterns with Validation
200+ regex patterns with false positive reduction through validation
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Callable, Dict
import string

@dataclass
class SecretPattern:
    """Represents a secret detection pattern with validation"""
    name: str
    regex: str
    category: str
    confidence: int  # 0-100, higher = more confident it's a real secret
    validator: Optional[str] = None  # Validation method name
    description: Optional[str] = None
    
    def compile(self):
        return re.compile(self.regex, re.IGNORECASE | re.MULTILINE)


class PatternValidator:
    """
    Enhanced validator to reduce false positives
    Filters out: minified JS, common words, test values, code snippets
    """
    
    # Common words and patterns that are NOT secrets
    FALSE_POSITIVE_PATTERNS = [
        # JavaScript/TypeScript code patterns
        r'function\s*\(',
        r'Object\.defineProperty',
        r'Object\.prototype',
        r'\.prototype\.',
        r'module\.exports',
        r'require\s*\(',
        r'import\s+',
        r'export\s+',
        r'class\s+\w+',
        r'extends\s+',
        r'constructor\s*\(',
        r'async\s+function',
        r'await\s+',
        r'\blet\s+\w+\s*=',
        r'\bconst\s+\w+\s*=',
        r'\bvar\s+\w+\s*=',
        r'return\s+',
        r'throw\s+',
        r'catch\s*\(',
        r'try\s*{',
        r'if\s*\(',
        r'else\s*{',
        r'for\s*\(',
        r'while\s*\(',
        r'switch\s*\(',
        r'case\s+',
        r'default\s*:',
        r'=>\s*{',
        r'\.then\s*\(',
        r'\.catch\s*\(',
        r'Promise\.',
        r'Array\.',
        r'String\.',
        r'Number\.',
        r'Boolean\.',
        r'\.map\s*\(',
        r'\.filter\s*\(',
        r'\.reduce\s*\(',
        r'\.forEach\s*\(',
        r'\.push\s*\(',
        r'\.pop\s*\(',
        r'\.shift\s*\(',
        r'JSON\.parse',
        r'JSON\.stringify',
        r'localStorage\.',
        r'sessionStorage\.',
        r'document\.',
        r'window\.',
        r'console\.',
        r'addEventListener',
        r'removeEventListener',
        r'createElement',
        r'getElementById',
        r'querySelector',
        r'innerHTML',
        r'textContent',
        r'appendChild',
        r'removeChild',
        r'classList\.',
        r'setAttribute',
        r'getAttribute',
        r'URLSearchParams',
        r'new\s+URL\s*\(',
        r'new\s+Date\s*\(',
        r'new\s+RegExp\s*\(',
        r'encodeURI',
        r'decodeURI',
        r'btoa\s*\(',
        r'atob\s*\(',
        # Common variable/function names
        r'^[a-z]\s*$',  # Single letter variables
        r'^[a-z]{1,2}\.[a-z]{1,2}\s*$',  # e.t, a.b style
        r'^\w+Regexp$',
        r'^escape\w+$',
        r'^\w+Handler$',
        r'^\w+Listener$',
        r'^\w+Callback$',
    ]
    
    # Words that indicate this is code, not a secret
    CODE_INDICATORS = [
        'function', 'object', 'array', 'string', 'number', 'boolean',
        'undefined', 'null', 'true', 'false', 'prototype', 'constructor',
        'defineProperty', 'hasOwnProperty', 'instanceof', 'typeof',
        'arguments', 'return', 'throw', 'catch', 'finally', 'debugger',
        'switch', 'case', 'default', 'break', 'continue', 'yield',
        'async', 'await', 'import', 'export', 'require', 'module',
        'extends', 'implements', 'interface', 'abstract', 'static',
        'public', 'private', 'protected', 'readonly', 'override',
        'enumerable', 'configurable', 'writable', 'value', 'get', 'set',
        'googletagmanager', 'gtag', 'analytics', 'tracking', 'pixel',
        'webpack', 'babel', 'polyfill', 'sourcemap', 'sourceMappingURL',
        'usestrict', 'use strict', 'esmodule', '__esModule',
    ]
    
    # Placeholder/example indicators
    PLACEHOLDER_PATTERNS = [
        'example', 'your_', 'your-', 'my_', 'my-', 'xxx', 'yyy', 'zzz',
        'test', 'demo', 'sample', 'fake', 'dummy', 'placeholder', 'changeme',
        'insert', 'todo', 'fixme', 'replace', 'enter_', 'put_', 'add_',
        '12345', 'abcdef', 'password123', 'secret123', 'apikey123',
        'aaaaa', 'bbbbb', '00000', '11111', 'qwerty', 
        'null', 'undefined', 'none', 'empty', 'blank', 'default',
        'foobar', 'foo_bar', 'lorem', 'ipsum', 'asdf',
        '<your', '{your', '${your', '{{your', '[your',
        '<api', '{api', '${api', '{{api', '[api',
        '<key', '{key', '${key', '{{key', '[key',
        '<token', '{token', '${token', '{{token', '[token',
        '<secret', '{secret', '${secret', '{{secret', '[secret',
    ]
    
    # URL patterns that are test/example URLs
    TEST_URL_PATTERNS = [
        r'//a/', r'//b/', r'//c/',  # Test URLs like //a/c%20d
        r'example\.com', r'example\.org', r'example\.net',
        r'localhost', r'127\.0\.0\.1', r'0\.0\.0\.0',
        r'test\.com', r'test\.org', r'foo\.bar',
        r'example-', r'-example', r'_example',
    ]
    
    def __init__(self):
        # Compile false positive patterns
        self._fp_patterns = [re.compile(p, re.IGNORECASE) for p in self.FALSE_POSITIVE_PATTERNS]
        self._test_url_patterns = [re.compile(p, re.IGNORECASE) for p in self.TEST_URL_PATTERNS]
        # Track seen values for deduplication
        self._seen_values = set()
    
    def reset_seen_values(self):
        """Reset seen values for new scan"""
        self._seen_values = set()
    
    @staticmethod
    def is_high_entropy(value: str, threshold: float = 3.8) -> bool:
        """Check if string has high entropy (likely random/secret)"""
        if len(value) < 10:  # Increased minimum length
            return False
        
        # Skip if too short or too long
        if len(value) > 500:
            return False
        
        # Calculate Shannon entropy
        prob = [float(value.count(c)) / len(value) for c in dict.fromkeys(list(value))]
        entropy = -sum([p * (p and (p / 0.6931471805599453)) for p in prob if p > 0])
        
        return entropy > threshold
    
    def is_minified_js(self, value: str) -> bool:
        """Check if value looks like minified JavaScript code"""
        # Check for common JS patterns
        for pattern in self._fp_patterns:
            if pattern.search(value):
                return True
        
        # Check for code indicators
        value_lower = value.lower()
        code_word_count = sum(1 for word in self.CODE_INDICATORS if word in value_lower)
        if code_word_count >= 2:
            return True
        
        # High density of special characters = likely code
        special_chars = sum(1 for c in value if c in '{}[]();:,=><+-*/&|!?')
        if len(value) > 0 and special_chars / len(value) > 0.15:
            return True
        
        # Contains arrow functions or JS syntax
        if '=>' in value or 'function(' in value.lower():
            return True
        
        # Multiple semicolons or braces = code
        if value.count(';') > 2 or value.count('{') > 2 or value.count('}') > 2:
            return True
        
        return False
    
    def is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder/example"""
        value_lower = value.lower()
        return any(p in value_lower for p in self.PLACEHOLDER_PATTERNS)
    
    def is_test_url(self, value: str) -> bool:
        """Check if value is a test/example URL"""
        for pattern in self._test_url_patterns:
            if pattern.search(value):
                return True
        return False
    
    def is_duplicate(self, value: str) -> bool:
        """Check if we've already seen this value"""
        # Normalize the value (remove whitespace, lowercase for comparison)
        normalized = value.strip().lower()[:100]  # First 100 chars for comparison
        
        if normalized in self._seen_values:
            return True
        
        self._seen_values.add(normalized)
        return False
    
    @staticmethod
    def is_valid_aws_key(value: str) -> bool:
        """Validate AWS Access Key ID format"""
        if not value.startswith('AKIA'):
            return False
        if len(value) != 20:
            return False
        # Must be uppercase alphanumeric after AKIA
        return value[4:].isalnum() and value[4:].isupper()
    
    @staticmethod
    def is_valid_jwt(value: str) -> bool:
        """Validate JWT format"""
        parts = value.split('.')
        if len(parts) != 3:
            return False
        
        # Each part should have minimum length
        if any(len(p) < 4 for p in parts):
            return False
        
        # Each part should be base64-ish
        try:
            for part in parts:
                if not part:
                    return False
                # Check for valid base64 characters
                valid_chars = set(string.ascii_letters + string.digits + '-_=')
                if not all(c in valid_chars for c in part):
                    return False
            return True
        except:
            return False
    
    @staticmethod
    def is_valid_github_token(value: str) -> bool:
        """Validate GitHub token format"""
        prefixes = ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_']
        if not any(value.startswith(p) for p in prefixes):
            return False
        # Token part should be alphanumeric
        token_part = value[4:]
        return len(token_part) >= 36 and token_part.isalnum()
    
    @staticmethod
    def is_valid_stripe_key(value: str) -> bool:
        """Validate Stripe API key format"""
        if not (value.startswith('sk_live_') or value.startswith('sk_test_') or 
                value.startswith('pk_live_') or value.startswith('pk_test_') or
                value.startswith('rk_live_')):
            return False
        key_part = value.split('_', 2)[-1]
        return len(key_part) >= 24 and key_part.isalnum()
    
    @staticmethod
    def is_not_common_variable(value: str) -> bool:
        """Check if value is not a common variable name"""
        common_vars = [
            'apikey', 'api_key', 'apiKey', 'API_KEY', 'token', 'TOKEN',
            'secret', 'SECRET', 'password', 'PASSWORD', 'key', 'KEY',
            'auth', 'AUTH', 'credential', 'CREDENTIAL'
        ]
        return value not in common_vars
    
    def validate(self, pattern, match: str) -> bool:
        """Run comprehensive validation for a pattern match"""
        # Skip very short or very long matches
        if len(match) < 8 or len(match) > 1000:
            return False
        
        # Check for duplicates first
        if self.is_duplicate(match):
            return False
        
        # Check if it's minified JS code
        if self.is_minified_js(match):
            return False
        
        # Check if it's a placeholder
        if self.is_placeholder(match):
            return False
        
        # Check if it's a test URL
        if self.is_test_url(match):
            return False
        
        # Run specific validator if specified
        if hasattr(pattern, 'validator') and pattern.validator:
            validator_method = getattr(self, pattern.validator, None)
            if validator_method:
                return validator_method(match)
        
        # For generic patterns, require high entropy
        if hasattr(pattern, 'category') and pattern.category in ['api', 'generic', 'password']:
            return self.is_high_entropy(match)
        
        return True


# ============================================
# CLOUD PROVIDERS (Enhanced)
# ============================================

CLOUD_PATTERNS = [
    # AWS
    SecretPattern("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "aws", 95, "is_valid_aws_key"),
    SecretPattern("AWS Secret Access Key", r"(?:aws_secret_access_key|aws_secret_key|secret_access_key)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "aws", 90),
    SecretPattern("AWS Session Token", r"(?:aws_session_token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?", "aws", 85),
    SecretPattern("AWS Account ID", r"(?:aws_account_id|account_id)['\"]?\s*[:=]\s*['\"]?([0-9]{12})['\"]?", "aws", 70),
    SecretPattern("AWS S3 Bucket", r"(?:s3://|s3\.amazonaws\.com/)([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])", "aws", 75),
    SecretPattern("AWS S3 URL", r"https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com", "aws", 70),
    SecretPattern("AWS ARN", r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:[a-zA-Z0-9-_/:.]+", "aws", 80),
    SecretPattern("AWS MWS Auth Token", r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "aws", 95),
    
    # Google Cloud
    SecretPattern("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "gcp", 90),
    SecretPattern("Google OAuth Token", r"ya29\.[0-9A-Za-z\-_]+", "gcp", 85),
    SecretPattern("Google Service Account", r'"type"\s*:\s*"service_account"', "gcp", 95),
    SecretPattern("Firebase URL", r"https?://[a-zA-Z0-9-]+\.firebaseio\.com", "gcp", 85),
    SecretPattern("Firebase Key", r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "gcp", 95),
    SecretPattern("GCP Project ID", r"(?:project_id|projectId)['\"]?\s*[:=]\s*['\"]?([a-z][a-z0-9-]{4,28}[a-z0-9])['\"]?", "gcp", 65),
    
    # Azure
    SecretPattern("Azure Storage Account Key", r"(?:AccountKey=)([A-Za-z0-9+/=]{88})", "azure", 95),
    SecretPattern("Azure Connection String", r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "azure", 95),
    SecretPattern("Azure SAS Token", r"[?&]sig=([A-Za-z0-9%]+)", "azure", 70),
    SecretPattern("Azure Client Secret", r"(?:client_secret|clientSecret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9~._-]{34,})['\"]?", "azure", 80),
    SecretPattern("Azure Tenant ID", r"(?:tenant_id|tenantId)['\"]?\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?", "azure", 70),
    
    # DigitalOcean
    SecretPattern("DigitalOcean Token", r"dop_v1_[a-f0-9]{64}", "digitalocean", 95),
    SecretPattern("DigitalOcean Spaces Key", r"(?:spaces_access_key)['\"]?\s*[:=]\s*['\"]?([A-Z0-9]{20})['\"]?", "digitalocean", 85),
    
    # Alibaba
    SecretPattern("Alibaba AccessKey ID", r"LTAI[A-Za-z0-9]{12,20}", "alibaba", 90),
    SecretPattern("Alibaba AccessKey Secret", r"(?:accessKeySecret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9]{30})['\"]?", "alibaba", 85),
]

# ============================================
# API KEYS & TOKENS (Enhanced)
# ============================================

API_PATTERNS = [
    # Generic (with high entropy validation)
    SecretPattern("API Key (Generic)", r"(?:api_key|apikey|api-key)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,64})['\"]?", "api", 60, "is_high_entropy"),
    SecretPattern("Secret Key (Generic)", r"(?:secret_key|secretkey|secret-key)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,64})['\"]?", "api", 55, "is_high_entropy"),
    SecretPattern("Access Token (Generic)", r"(?:access_token|accessToken)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,100})['\"]?", "api", 50, "is_high_entropy"),
    SecretPattern("Private Key (Generic)", r"(?:private_key|privateKey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-/+=]{20,})['\"]?", "api", 60, "is_high_entropy"),
    
    # Stripe
    SecretPattern("Stripe Live Secret Key", r"sk_live_[0-9a-zA-Z]{24,}", "stripe", 95, "is_valid_stripe_key"),
    SecretPattern("Stripe Test Secret Key", r"sk_test_[0-9a-zA-Z]{24,}", "stripe", 75),
    SecretPattern("Stripe Restricted Key", r"rk_live_[0-9a-zA-Z]{24,}", "stripe", 95),
    SecretPattern("Stripe Publishable Key", r"pk_(?:live|test)_[0-9a-zA-Z]{24,}", "stripe", 65),
    SecretPattern("Stripe Webhook Secret", r"whsec_[0-9a-zA-Z]{24,}", "stripe", 90),
    
    # Twilio
    SecretPattern("Twilio Account SID", r"AC[a-fA-F0-9]{32}", "twilio", 90),
    SecretPattern("Twilio Auth Token", r"(?:twilio_auth_token|authToken)['\"]?\s*[:=]\s*['\"]?([a-fA-F0-9]{32})['\"]?", "twilio", 85),
    SecretPattern("Twilio API Key", r"SK[0-9a-fA-F]{32}", "twilio", 90),
    
    # SendGrid
    SecretPattern("SendGrid API Key", r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "sendgrid", 95),
    
    # Mailgun
    SecretPattern("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", "mailgun", 95),
    SecretPattern("Mailgun Domain Key", r"(?:mailgun)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?", "mailgun", 80),
    
    # MailChimp
    SecretPattern("MailChimp API Key", r"[0-9a-f]{32}-us[0-9]{1,2}", "mailchimp", 95),
    
    # PayPal
    SecretPattern("PayPal Client ID", r"(?:paypal_client_id|client_id)['\"]?\s*[:=]\s*['\"]?(A[A-Za-z0-9_-]{60,80})['\"]?", "paypal", 75),
    SecretPattern("PayPal Secret", r"(?:paypal_secret|client_secret)['\"]?\s*[:=]\s*['\"]?(E[A-Za-z0-9_-]{60,80})['\"]?", "paypal", 85),
    SecretPattern("PayPal Braintree Token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "paypal", 95),
    
    # Square
    SecretPattern("Square Access Token", r"sq0atp-[0-9A-Za-z\-_]{22,}", "square", 95),
    SecretPattern("Square OAuth Secret", r"sq0csp-[0-9A-Za-z\-_]{43,}", "square", 95),
    SecretPattern("Square Application ID", r"sq0idp-[0-9A-Za-z\-_]{22,}", "square", 80),
    
    # Shopify
    SecretPattern("Shopify Private Token", r"shppa_[a-fA-F0-9]{32}", "shopify", 95),
    SecretPattern("Shopify Shared Secret", r"shpss_[a-fA-F0-9]{32}", "shopify", 95),
    SecretPattern("Shopify Access Token", r"shpat_[a-fA-F0-9]{32}", "shopify", 95),
    SecretPattern("Shopify Custom Token", r"shpca_[a-fA-F0-9]{32}", "shopify", 95),
    
    # Intercom
    SecretPattern("Intercom Access Token", r"(?:intercom)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9=_]{60})['\"]?", "intercom", 80),
    
    # Zendesk
    SecretPattern("Zendesk API Token", r"(?:zendesk_api_token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{40})['\"]?", "zendesk", 80),
]

# ============================================
# SOCIAL & MESSAGING (Enhanced)
# ============================================

SOCIAL_PATTERNS = [
    # GitHub
    SecretPattern("GitHub PAT", r"ghp_[0-9a-zA-Z]{36,}", "github", 95, "is_valid_github_token"),
    SecretPattern("GitHub OAuth Token", r"gho_[0-9a-zA-Z]{36,}", "github", 95),
    SecretPattern("GitHub App Token", r"(?:ghu|ghs)_[0-9a-zA-Z]{36,}", "github", 95),
    SecretPattern("GitHub Fine-Grained PAT", r"github_pat_[0-9a-zA-Z_]{82,}", "github", 95),
    SecretPattern("GitHub Refresh Token", r"ghr_[0-9a-zA-Z]{36,76}", "github", 95),
    SecretPattern("GitHub App Installation Token", r"v1\.[0-9a-f]{40}", "github", 80),
    
    # GitLab
    SecretPattern("GitLab PAT", r"glpat-[0-9a-zA-Z\-_]{20,}", "gitlab", 95),
    SecretPattern("GitLab Pipeline Token", r"glptt-[0-9a-fA-F]{40,}", "gitlab", 95),
    SecretPattern("GitLab Runner Token", r"GR1348941[0-9a-zA-Z\-_]{20,}", "gitlab", 90),
    
    # Bitbucket
    SecretPattern("Bitbucket App Password", r"(?:bitbucket)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{18,})['\"]?", "bitbucket", 75),
    
    # Slack
    SecretPattern("Slack Bot Token", r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", "slack", 95),
    SecretPattern("Slack User Token", r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}", "slack", 95),
    SecretPattern("Slack App Token", r"xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]+", "slack", 95),
    SecretPattern("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,12}/[a-zA-Z0-9]{24}", "slack", 95),
    SecretPattern("Slack Configuration Token", r"xoxe\.xoxp-[0-9]-[a-zA-Z0-9]{146,}", "slack", 90),
    
    # Discord
    SecretPattern("Discord Bot Token", r"[MN][A-Za-z\d]{23,26}\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27,}", "discord", 95),
    SecretPattern("Discord Webhook", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "discord", 95),
    SecretPattern("Discord Client Secret", r"(?:discord_client_secret)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{32})['\"]?", "discord", 85),
    
    # Telegram
    SecretPattern("Telegram Bot Token", r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}", "telegram", 95),
    
    # Facebook
    SecretPattern("Facebook Access Token", r"EAACEdEose0cBA[0-9A-Za-z]+", "facebook", 95),
    SecretPattern("Facebook App Secret", r"(?:facebook_app_secret|fb_app_secret)['\"]?\s*[:=]\s*['\"]?([0-9a-f]{32})['\"]?", "facebook", 85),
    SecretPattern("Facebook Client Token", r"(?:facebook_client_token)['\"]?\s*[:=]\s*['\"]?([0-9a-f]{32})['\"]?", "facebook", 80),
    
    # Twitter/X
    SecretPattern("Twitter Bearer Token", r"AAAAAAAAA[a-zA-Z0-9%]{80,}", "twitter", 90),
    SecretPattern("Twitter API Key", r"(?:twitter_api_key|consumer_key)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{25})['\"]?", "twitter", 80),
    SecretPattern("Twitter API Secret", r"(?:twitter_api_secret|consumer_secret)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{50})['\"]?", "twitter", 85),
    SecretPattern("Twitter Access Token", r"[0-9]{15,25}-[a-zA-Z0-9]{40,50}", "twitter", 85),
    
    # LinkedIn
    SecretPattern("LinkedIn Client Secret", r"(?:linkedin_client_secret)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{16})['\"]?", "linkedin", 80),
    
    # Instagram
    SecretPattern("Instagram Access Token", r"IGQ[a-zA-Z0-9_-]{100,}", "instagram", 90),
]

# ============================================
# AUTHENTICATION & CREDENTIALS (Enhanced)
# ============================================

AUTH_PATTERNS = [
    # JWT
    SecretPattern("JWT Token", r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*", "jwt", 85, "is_valid_jwt"),
    
    # OAuth
    SecretPattern("OAuth Client ID", r"(?:client_id|clientId)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,100})['\"]?", "oauth", 50),
    SecretPattern("OAuth Client Secret", r"(?:client_secret|clientSecret)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,100})['\"]?", "oauth", 70, "is_high_entropy"),
    SecretPattern("OAuth Refresh Token", r"(?:refresh_token|refreshToken)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,200})['\"]?", "oauth", 65),
    
    # Bearer/Basic Auth
    SecretPattern("Bearer Token", r"[Bb]earer\s+([a-zA-Z0-9\-_.=]{20,500})", "auth", 70),
    SecretPattern("Basic Auth", r"[Bb]asic\s+([a-zA-Z0-9+/=]{20,100})", "auth", 65),
    SecretPattern("Authorization Header", r"[Aa]uthorization['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_.=+/ ]{20,})['\"]?", "auth", 60),
    
    # Passwords
    SecretPattern("Password in URL", r"(?:://)[^:]+:([^@]+)@", "password", 90),
    SecretPattern("Password Assignment", r"(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,50})['\"]?", "password", 50, "is_high_entropy"),
    SecretPattern("Hardcoded Password", r"(?:PASSWORD|PASSWD)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,50})['\"]?", "password", 60, "is_high_entropy"),
    
    # Private Keys
    SecretPattern("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "keys", 99),
    SecretPattern("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "keys", 99),
    SecretPattern("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "keys", 99),
    SecretPattern("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "keys", 99),
    SecretPattern("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "keys", 99),
    SecretPattern("Encrypted Private Key", r"-----BEGIN ENCRYPTED PRIVATE KEY-----", "keys", 95),
    SecretPattern("Private Key (Generic)", r"-----BEGIN [A-Z ]+ PRIVATE KEY-----", "keys", 99),
    
    # Database Connection Strings
    SecretPattern("MongoDB URI", r"mongodb(?:\+srv)?://[^\s'\"]+", "database", 85),
    SecretPattern("PostgreSQL URI", r"postgres(?:ql)?://[^\s'\"]+", "database", 85),
    SecretPattern("MySQL URI", r"mysql://[^\s'\"]+", "database", 85),
    SecretPattern("Redis URI", r"redis://[^\s'\"]+", "database", 80),
    SecretPattern("MSSQL Connection", r"(?:Server|Data Source)=[^;]+;(?:User|Uid)=[^;]+;(?:Password|Pwd)=[^;]+", "database", 90),
]

# ============================================
# DEVOPS & CI/CD (Enhanced)
# ============================================

DEVOPS_PATTERNS = [
    # NPM
    SecretPattern("NPM Access Token", r"npm_[a-zA-Z0-9]{36}", "npm", 95),
    SecretPattern("NPM Auth Token", r"//registry\.npmjs\.org/:_authToken=([a-f0-9-]{36})", "npm", 95),
    
    # PyPI
    SecretPattern("PyPI Token", r"pypi-[a-zA-Z0-9_-]{100,}", "pypi", 95),
    
    # Docker
    SecretPattern("Docker Auth", r"(?:docker_auth|dockerAuth)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9+/=]{20,})['\"]?", "docker", 75),
    SecretPattern("Docker Registry Token", r"(?:registry_token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?", "docker", 80),
    
    # Kubernetes
    SecretPattern("Kubernetes Service Token", r"(?:kubernetes_token|k8s_token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_.-]{50,})['\"]?", "kubernetes", 85),
    
    # Heroku
    SecretPattern("Heroku API Key", r"(?:heroku_api_key)['\"]?\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?", "heroku", 90),
    
    # Vercel
    SecretPattern("Vercel Token", r"(?:vercel_token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{24})['\"]?", "vercel", 85),
    
    # Netlify
    SecretPattern("Netlify Token", r"(?:netlify_token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{40,})['\"]?", "netlify", 85),
    
    # CircleCI
    SecretPattern("CircleCI Token", r"(?:circle_token|circleci_token)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{40})['\"]?", "circleci", 90),
    
    # Travis CI
    SecretPattern("Travis CI Token", r"(?:travis_token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{22})['\"]?", "travis", 85),
    
    # Jenkins
    SecretPattern("Jenkins Token", r"(?:jenkins_token|jenkins_api_token)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32,})['\"]?", "jenkins", 85),
    
    # Artifactory
    SecretPattern("Artifactory Token", r"AKC[a-zA-Z0-9]{10,}", "artifactory", 90),
    SecretPattern("Artifactory Password", r"AP[\dABCDEF][a-zA-Z0-9]{8,}", "artifactory", 85),
    
    # SonarQube
    SecretPattern("SonarQube Token", r"sqp_[a-f0-9]{40}", "sonarqube", 95),
    
    # Sentry
    SecretPattern("Sentry DSN", r"https://[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/[0-9]+", "sentry", 90),
    SecretPattern("Sentry Auth Token", r"(?:sentry_auth_token)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{64})['\"]?", "sentry", 90),
    
    # Datadog
    SecretPattern("Datadog API Key", r"(?:datadog_api_key|dd_api_key)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?", "datadog", 90),
    SecretPattern("Datadog App Key", r"(?:datadog_app_key|dd_app_key)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{40})['\"]?", "datadog", 90),
    
    # New Relic
    SecretPattern("New Relic License Key", r"(?:new_relic_license_key)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{40})['\"]?", "newrelic", 90),
    SecretPattern("New Relic API Key", r"NRAK-[A-Z0-9]{27}", "newrelic", 95),
    
    # PagerDuty
    SecretPattern("PagerDuty API Key", r"(?:pagerduty)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9+]{20})['\"]?", "pagerduty", 80),
    
    # LaunchDarkly
    SecretPattern("LaunchDarkly SDK Key", r"sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "launchdarkly", 95),
    SecretPattern("LaunchDarkly API Key", r"api-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "launchdarkly", 95),
    
    # Algolia
    SecretPattern("Algolia API Key", r"(?:algolia_api_key)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?", "algolia", 85),
    SecretPattern("Algolia Admin Key", r"(?:algolia_admin_key)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?", "algolia", 90),
]

# ============================================
# ENDPOINTS & SENSITIVE URLS
# ============================================

ENDPOINT_PATTERNS = [
    # Internal/Admin APIs
    SecretPattern("Internal API", r"['\"]/(internal|admin|debug|private|api/v[0-9]+/admin)[^'\"]*['\"]", "endpoint", 75),
    SecretPattern("Hidden API Route", r"['\"]/(api|rest|graphql|v[0-9]+)/[a-z_/-]*['\"]", "endpoint", 50),
    SecretPattern("GraphQL Endpoint", r"['\"]/(graphql|gql)['\"]", "endpoint", 60),
    SecretPattern("WebSocket URL", r"wss?://[^\s'\"]+", "endpoint", 55),
    
    # Cloud Resources
    SecretPattern("AWS S3 URL", r"https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com[^\s'\"]*", "url", 70),
    SecretPattern("Azure Blob URL", r"https?://[a-z0-9]+\.blob\.core\.windows\.net[^\s'\"]*", "url", 70),
    SecretPattern("GCS Bucket URL", r"https?://storage\.googleapis\.com/[^\s'\"]+", "url", 70),
    
    # Development/Staging
    SecretPattern("Dev/Staging URL", r"https?://(dev|staging|test|uat|qa)[.-][^\s'\"]+", "url", 60),
    SecretPattern("Localhost URL", r"https?://(localhost|127\.0\.0\.1)(:[0-9]+)?[^\s'\"]*", "url", 40),
]


# ============================================
# ALL PATTERNS COMBINED
# ============================================

ALL_PATTERNS: List[SecretPattern] = (
    CLOUD_PATTERNS +
    API_PATTERNS +
    SOCIAL_PATTERNS +
    AUTH_PATTERNS +
    DEVOPS_PATTERNS +
    ENDPOINT_PATTERNS
)


def get_patterns_by_category(category: str) -> List[SecretPattern]:
    """Get patterns filtered by category"""
    return [p for p in ALL_PATTERNS if p.category == category]


def get_high_confidence_patterns(min_confidence: int = 80) -> List[SecretPattern]:
    """Get patterns with confidence >= min_confidence"""
    return [p for p in ALL_PATTERNS if p.confidence >= min_confidence]


def compile_all_patterns() -> Dict[str, re.Pattern]:
    """Compile all patterns for efficient matching"""
    return {p.name: p.compile() for p in ALL_PATTERNS}


# Total pattern count
TOTAL_PATTERNS = len(ALL_PATTERNS)
