"""
NightCrawler v3.0 - KeyHacks Auto-Validator
Automatically validate discovered secrets using API calls
Based on: https://github.com/streaak/keyhacks

⚠️ ETHICAL USE ONLY ⚠️
This tool is designed for:
- Bug Bounty Programs (with explicit permission)
- Authorized Security Assessments
- Penetration Testing (with signed authorization)

DO NOT use this tool for unauthorized access or malicious purposes.
The author is not responsible for any misuse of this tool.

by CyberTechAjju | Keep Learning // Keep Hacking
"""

import subprocess
import asyncio
import aiohttp
import json
import re
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
from enum import Enum
from rich.console import Console

console = Console()


class ValidationStatus(Enum):
    """Validation result status"""
    VALID = "VALID"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    PARTIAL = "PARTIAL"  # Some permissions work


@dataclass
class ValidationResult:
    """Result of secret validation"""
    status: ValidationStatus
    message: str
    permissions: Optional[List[str]] = None
    raw_response: Optional[str] = None
    validation_command: Optional[str] = None


# ============================================
# KEYHACKS VALIDATION DATABASE
# 50+ API validation commands
# ============================================

KEYHACKS_VALIDATORS = {
    # ==========================================
    # CLOUD PROVIDERS
    # ==========================================
    
    "AWS Access Key": {
        "type": "command",
        "command": "AWS_ACCESS_KEY_ID={key} AWS_SECRET_ACCESS_KEY={secret} aws sts get-caller-identity --output json 2>/dev/null",
        "success_indicators": ["Account", "UserId", "Arn"],
        "failure_indicators": ["InvalidClientTokenId", "SignatureDoesNotMatch"],
        "requires_pair": True,
        "pair_pattern": "AWS Secret Key",
        "description": "Validates AWS credentials by calling STS GetCallerIdentity"
    },
    
    "Google API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={key}",
        "success_indicators": ["audience", "scope", "expires_in"],
        "failure_indicators": ["invalid_token", "Invalid Value"],
        "alt_validation": {
            "url": "https://maps.googleapis.com/maps/api/geocode/json?address=test&key={key}",
            "success_indicators": ["results", "status"],
            "failure_indicators": ["REQUEST_DENIED", "InvalidKeyMapError"]
        },
        "description": "Validates Google API key using OAuth tokeninfo or Maps API"
    },
    
    "Firebase Key": {
        "type": "http",
        "method": "POST",
        "url": "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={key}",
        "headers": {"Content-Type": "application/json"},
        "body": "{}",
        "success_indicators": ["idToken", "refreshToken", "kind"],
        "failure_indicators": ["API_KEY_INVALID", "INVALID_API_KEY"],
        "description": "Validates Firebase API key by attempting anonymous signup"
    },
    
    # ==========================================
    # PAYMENT PROCESSORS
    # ==========================================
    
    "Stripe Live Secret Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.stripe.com/v1/charges",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "",
        "success_indicators": ["data", "object", "has_more"],
        "failure_indicators": ["Invalid API Key", "api_key_expired"],
        "description": "Validates Stripe key by listing charges"
    },
    
    "Stripe Test Secret Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.stripe.com/v1/charges",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "",
        "success_indicators": ["data", "object"],
        "failure_indicators": ["Invalid API Key"],
        "description": "Validates Stripe test key (less critical but still validates)"
    },
    
    "PayPal Braintree Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.braintreegateway.com/merchants/{merchant_id}",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["merchant", "id"],
        "failure_indicators": ["Unauthorized", "Invalid"],
        "description": "Validates Braintree/PayPal token"
    },
    
    "Square Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://connect.squareup.com/v2/locations",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["locations"],
        "failure_indicators": ["UNAUTHORIZED", "AUTHENTICATION_ERROR"],
        "description": "Validates Square API token by listing locations"
    },
    
    "Razorpay API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.razorpay.com/v1/payments",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "{secret}",
        "requires_pair": True,
        "success_indicators": ["entity", "count", "items"],
        "failure_indicators": ["BAD_REQUEST_ERROR", "Unauthorized"],
        "description": "Validates Razorpay API key and secret"
    },
    
    # ==========================================
    # SOURCE CONTROL & CI/CD
    # ==========================================
    
    "GitHub PAT": {
        "type": "http",
        "method": "GET",
        "url": "https://api.github.com/user",
        "headers": {"Authorization": "Bearer {key}", "Accept": "application/vnd.github+json"},
        "success_indicators": ["login", "id", "email"],
        "failure_indicators": ["Bad credentials", "Requires authentication"],
        "permission_check": {
            "url": "https://api.github.com/rate_limit",
            "headers": {"Authorization": "Bearer {key}"},
            "scope_header": "X-OAuth-Scopes"
        },
        "description": "Validates GitHub token and checks scopes"
    },
    
    "GitHub Personal Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.github.com/user",
        "headers": {"Authorization": "token {key}"},
        "success_indicators": ["login", "id"],
        "failure_indicators": ["Bad credentials"],
        "description": "Validates GitHub classic PAT"
    },
    
    "GitLab PAT": {
        "type": "http",
        "method": "GET",
        "url": "https://gitlab.com/api/v4/user",
        "headers": {"PRIVATE-TOKEN": "{key}"},
        "success_indicators": ["id", "username", "email"],
        "failure_indicators": ["401 Unauthorized"],
        "description": "Validates GitLab personal access token"
    },
    
    "CircleCI Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://circleci.com/api/v1.1/me?circle-token={key}",
        "success_indicators": ["name", "login", "id"],
        "failure_indicators": ["Permission denied", "Must provide API token"],
        "description": "Validates CircleCI API token"
    },
    
    "Travis CI API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.travis-ci.com/user",
        "headers": {"Travis-API-Version": "3", "Authorization": "token {key}"},
        "success_indicators": ["@type", "id", "login"],
        "failure_indicators": ["access denied", "insufficient_access"],
        "description": "Validates Travis CI API token"
    },
    
    "NPM Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://registry.npmjs.org/-/npm/v1/user",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["name", "email"],
        "failure_indicators": ["Unauthorized", "invalid token"],
        "description": "Validates NPM access token"
    },
    
    # ==========================================
    # MESSAGING & COMMUNICATION
    # ==========================================
    
    "Slack Bot Token": {
        "type": "http",
        "method": "POST",
        "url": "https://slack.com/api/auth.test",
        "headers": {"Authorization": "Bearer {key}", "Content-Type": "application/json"},
        "success_indicators": ["ok", "user", "team"],
        "failure_indicators": ["invalid_auth", "not_authed"],
        "description": "Validates Slack bot token"
    },
    
    "Slack User Token": {
        "type": "http",
        "method": "POST",
        "url": "https://slack.com/api/auth.test",
        "data": {"token": "{key}"},
        "success_indicators": ["ok", "user_id"],
        "failure_indicators": ["invalid_auth"],
        "description": "Validates Slack user token (xoxp)"
    },
    
    "Slack Webhook": {
        "type": "http",
        "method": "POST",
        "url": "{key}",
        "headers": {"Content-Type": "application/json"},
        "body": '{"text":""}',
        "success_indicators": ["missing_text_or_fallback_or_attachments"],
        "failure_indicators": ["invalid_payload", "channel_not_found", "Webhook URL"],
        "description": "Validates Slack webhook by sending empty message"
    },
    
    "Discord Webhook": {
        "type": "http",
        "method": "GET",
        "url": "{key}",
        "success_indicators": ["id", "token", "name", "channel_id"],
        "failure_indicators": ["Unknown Webhook", "Invalid Webhook Token"],
        "description": "Validates Discord webhook by GET request"
    },
    
    "Discord Bot Token": {
        "type": "http",
        "method": "GET",
        "url": "https://discord.com/api/v10/users/@me",
        "headers": {"Authorization": "Bot {key}"},
        "success_indicators": ["id", "username", "discriminator"],
        "failure_indicators": ["401: Unauthorized", "Invalid Token"],
        "description": "Validates Discord bot token"
    },
    
    "Telegram Bot Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.telegram.org/bot{key}/getMe",
        "success_indicators": ["ok", "result", "username"],
        "failure_indicators": ["Not Found", "Unauthorized"],
        "description": "Validates Telegram bot token"
    },
    
    "Twilio Account SID": {
        "type": "http",
        "method": "GET",
        "url": "https://api.twilio.com/2010-04-01/Accounts/{key}.json",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "{secret}",
        "requires_pair": True,
        "pair_pattern": "Twilio Auth Token",
        "success_indicators": ["account_sid", "status", "friendly_name"],
        "failure_indicators": ["Authenticate", "invalid username"],
        "description": "Validates Twilio Account SID and Auth Token"
    },
    
    # ==========================================
    # EMAIL SERVICES
    # ==========================================
    
    "SendGrid API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.sendgrid.com/v3/scopes",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["scopes"],
        "failure_indicators": ["authorization required", "The provided authorization"],
        "description": "Validates SendGrid API key and lists scopes"
    },
    
    "MailGun API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.mailgun.net/v3/domains",
        "auth": "basic",
        "auth_user": "api",
        "auth_pass": "{key}",
        "success_indicators": ["items", "total_count"],
        "failure_indicators": ["Forbidden", "Unauthorized"],
        "description": "Validates Mailgun API key"
    },
    
    "MailChimp API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://{dc}.api.mailchimp.com/3.0/",
        "auth": "basic",
        "auth_user": "anystring",
        "auth_pass": "{key}",
        "extract_dc": True,  # Extract datacenter from key (last part after -)
        "success_indicators": ["account_id", "account_name"],
        "failure_indicators": ["API Key Invalid", "Wrong"],
        "description": "Validates MailChimp API key"
    },
    
    # ==========================================
    # CLOUD INFRASTRUCTURE
    # ==========================================
    
    "Heroku API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.heroku.com/apps",
        "headers": {"Authorization": "Bearer {key}", "Accept": "application/vnd.heroku+json; version=3"},
        "success_indicators": ["id", "name", "web_url"],
        "failure_indicators": ["Invalid credentials", "Unauthorized"],
        "description": "Validates Heroku API key"
    },
    
    "DigitalOcean Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.digitalocean.com/v2/account",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["account", "email", "uuid"],
        "failure_indicators": ["Unable to authenticate", "unauthorized"],
        "description": "Validates DigitalOcean API token"
    },
    
    "Cloudflare API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.cloudflare.com/client/v4/user/tokens/verify",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["success", "result"],
        "failure_indicators": ["Invalid API Token", "Authentication error"],
        "description": "Validates Cloudflare API token"
    },
    
    "Vercel Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.vercel.com/v2/user",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["user", "id", "email"],
        "failure_indicators": ["Invalid token", "FORBIDDEN"],
        "description": "Validates Vercel deployment token"
    },
    
    "Netlify Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.netlify.com/api/v1/sites",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["id", "name", "url"],
        "failure_indicators": ["Invalid access token", "Unauthorized"],
        "description": "Validates Netlify access token"
    },
    
    # ==========================================
    # MONITORING & ANALYTICS
    # ==========================================
    
    "Datadog API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.datadoghq.com/api/v1/validate",
        "headers": {"DD-API-KEY": "{key}"},
        "success_indicators": ["valid"],
        "failure_indicators": ["Forbidden", "Invalid API key"],
        "description": "Validates Datadog API key"
    },
    
    "New Relic API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.newrelic.com/v2/applications.json",
        "headers": {"X-Api-Key": "{key}"},
        "success_indicators": ["applications"],
        "failure_indicators": ["Invalid API key", "Unauthorized"],
        "description": "Validates New Relic API key"
    },
    
    "Sentry Auth Token": {
        "type": "http",
        "method": "GET",
        "url": "https://sentry.io/api/0/",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["version", "user"],
        "failure_indicators": ["Invalid token", "Unauthorized"],
        "description": "Validates Sentry auth token"
    },
    
    "PagerDuty API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.pagerduty.com/users?limit=1",
        "headers": {"Authorization": "Token token={key}"},
        "success_indicators": ["users", "offset"],
        "failure_indicators": ["Invalid credentials", "Unauthorized Access"],
        "description": "Validates PagerDuty API key"
    },
    
    # ==========================================
    # SOCIAL & MARKETING
    # ==========================================
    
    "Facebook Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://graph.facebook.com/v18.0/me?access_token={key}",
        "success_indicators": ["id", "name"],
        "failure_indicators": ["Invalid OAuth access token", "OAuthException"],
        "description": "Validates Facebook access token"
    },
    
    "Twitter Bearer Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.twitter.com/2/tweets/search/recent?query=test",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["data", "meta"],
        "failure_indicators": ["Unauthorized", "Invalid Token"],
        "description": "Validates Twitter/X Bearer token"
    },
    
    "Instagram Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://graph.instagram.com/me?fields=id,username&access_token={key}",
        "success_indicators": ["id", "username"],
        "failure_indicators": ["Invalid OAuth", "OAuthException"],
        "description": "Validates Instagram Graph API token"
    },
    
    "LinkedIn Client Secret": {
        "type": "http",
        "method": "GET",
        "url": "https://api.linkedin.com/v2/me",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["id", "localizedFirstName"],
        "failure_indicators": ["Unauthorized", "Invalid access token"],
        "description": "Validates LinkedIn access token"
    },
    
    # ==========================================
    # SECURITY & RECON
    # ==========================================
    
    "Shodan API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.shodan.io/api-info?key={key}",
        "success_indicators": ["query_credits", "scan_credits", "plan"],
        "failure_indicators": ["Invalid API key", "Access denied"],
        "description": "Validates Shodan API key"
    },
    
    "VirusTotal API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://www.virustotal.com/api/v3/users/{key}",
        "headers": {"x-apikey": "{key}"},
        "success_indicators": ["data", "id"],
        "failure_indicators": ["NotFoundError", "ForbiddenError"],
        "description": "Validates VirusTotal API key"
    },
    
    "Censys API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://search.censys.io/api/v1/account",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "{secret}",
        "requires_pair": True,
        "success_indicators": ["email", "quota"],
        "failure_indicators": ["Unauthorized"],
        "description": "Validates Censys API credentials"
    },
    
    # ==========================================
    # MISC SERVICES
    # ==========================================
    
    "OpenAI API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.openai.com/v1/models",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["data", "object"],
        "failure_indicators": ["invalid_api_key", "Incorrect API key"],
        "description": "Validates OpenAI API key"
    },
    
    "Algolia API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://{app_id}-dsn.algolia.net/1/keys/{key}",
        "headers": {"X-Algolia-Application-Id": "{app_id}", "X-Algolia-API-Key": "{key}"},
        "success_indicators": ["acl", "validity"],
        "failure_indicators": ["Invalid API key", "IndexNotFoundException"],
        "description": "Validates Algolia API key"
    },
    
    "Mapbox API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.mapbox.com/tokens/v2?access_token={key}",
        "success_indicators": ["token", "scopes"],
        "failure_indicators": ["Not Authorized", "Invalid token"],
        "description": "Validates Mapbox access token"
    },
    
    "HubSpot API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.hubapi.com/crm/v3/objects/contacts?limit=1",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["results", "paging"],
        "failure_indicators": ["INVALID_AUTHENTICATION", "Invalid API key"],
        "description": "Validates HubSpot API key"
    },
    
    "Asana Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://app.asana.com/api/1.0/users/me",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["data", "gid", "name"],
        "failure_indicators": ["Not Authorized", "Invalid token"],
        "description": "Validates Asana personal access token"
    },
    
    "Zendesk API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://{subdomain}.zendesk.com/api/v2/users/me.json",
        "auth": "basic",
        "auth_user": "{email}/token",
        "auth_pass": "{key}",
        "success_indicators": ["user", "id"],
        "failure_indicators": ["Couldn't authenticate", "Invalid credentials"],
        "description": "Validates Zendesk API token (requires subdomain)"
    },
    
    "Grafana Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://grafana.com/api/user",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["id", "name", "login"],
        "failure_indicators": ["Unauthorized", "invalid API key"],
        "description": "Validates Grafana Cloud access token"
    },
    
    "Spotify Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.spotify.com/v1/me",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["id", "display_name"],
        "failure_indicators": ["Invalid access token", "token expired"],
        "description": "Validates Spotify access token"
    },
    
    "YouTube API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://www.googleapis.com/youtube/v3/channels?part=id&mine=true&key={key}",
        "success_indicators": ["kind", "items"],
        "failure_indicators": ["API key not valid", "keyInvalid"],
        "description": "Validates YouTube Data API key"
    },
    
    # ==========================================
    # SECRETS NINJA - ADDITIONAL VALIDATORS
    # ==========================================
    
    "Notion API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.notion.com/v1/users/me",
        "headers": {"Authorization": "Bearer {key}", "Notion-Version": "2022-06-28"},
        "success_indicators": ["object", "id", "type"],
        "failure_indicators": ["unauthorized", "invalid_token"],
        "description": "Validates Notion integration token"
    },
    
    "Figma Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.figma.com/v1/me",
        "headers": {"X-Figma-Token": "{key}"},
        "success_indicators": ["id", "email", "handle"],
        "failure_indicators": ["Invalid token", "Not authorized"],
        "description": "Validates Figma personal access token"
    },
    
    "Airtable PAT": {
        "type": "http",
        "method": "GET",
        "url": "https://api.airtable.com/v0/meta/whoami",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["id", "email", "scopes"],
        "failure_indicators": ["AUTHENTICATION_REQUIRED", "INVALID_PERMISSIONS_OR_MODEL"],
        "description": "Validates Airtable personal access token"
    },
    
    "Linear API Key": {
        "type": "http",
        "method": "POST",
        "url": "https://api.linear.app/graphql",
        "headers": {"Authorization": "{key}", "Content-Type": "application/json"},
        "body": '{"query":"{ viewer { id email } }"}',
        "success_indicators": ["data", "viewer", "email"],
        "failure_indicators": ["AUTHENTICATION_ERROR", "UNAUTHENTICATED"],
        "description": "Validates Linear API key using GraphQL"
    },
    
    "Jira API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://{domain}.atlassian.net/rest/api/3/myself",
        "auth": "basic",
        "auth_user": "{email}",
        "auth_pass": "{key}",
        "success_indicators": ["accountId", "emailAddress", "displayName"],
        "failure_indicators": ["Unauthorized", "Basic authentication"],
        "description": "Validates Jira/Atlassian API token (requires domain and email)"
    },
    
    "Confluence API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://{domain}.atlassian.net/wiki/rest/api/user/current",
        "auth": "basic",
        "auth_user": "{email}",
        "auth_pass": "{key}",
        "success_indicators": ["type", "username", "accountId"],
        "failure_indicators": ["Unauthorized", "authentication required"],
        "description": "Validates Confluence API token"
    },
    
    "Anthropic API Key": {
        "type": "http",
        "method": "POST",
        "url": "https://api.anthropic.com/v1/messages",
        "headers": {"x-api-key": "{key}", "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
        "body": '{"model":"claude-3-sonnet-20240229","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}',
        "success_indicators": ["content", "model", "id"],
        "failure_indicators": ["invalid_api_key", "authentication_error"],
        "description": "Validates Anthropic/Claude API key"
    },
    
    "Supabase API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://{project_ref}.supabase.co/rest/v1/",
        "headers": {"apikey": "{key}", "Authorization": "Bearer {key}"},
        "success_indicators": ["swagger", "info"],
        "failure_indicators": ["Invalid API key", "JWT"],
        "description": "Validates Supabase anon/service key"
    },
    
    "PlanetScale API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.planetscale.com/v1/organizations",
        "headers": {"Authorization": "{key}"},
        "success_indicators": ["data", "type"],
        "failure_indicators": ["Unauthorized", "invalid_token"],
        "description": "Validates PlanetScale API token"
    },
    
    "Clerk API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.clerk.com/v1/users?limit=1",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["data", "total_count"],
        "failure_indicators": ["authorization_invalid", "Unauthorized"],
        "description": "Validates Clerk secret key"
    },
    
    "Auth0 Management Token": {
        "type": "http",
        "method": "GET",
        "url": "https://{domain}.auth0.com/api/v2/users?per_page=1",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["user_id", "email"],
        "failure_indicators": ["Unauthorized", "invalid_token"],
        "description": "Validates Auth0 Management API token"
    },
    
    "Plaid API Key": {
        "type": "http",
        "method": "POST",
        "url": "https://sandbox.plaid.com/institutions/get",
        "headers": {"Content-Type": "application/json"},
        "body": '{"client_id":"{client_id}","secret":"{key}","count":1,"offset":0,"country_codes":["US"]}',
        "success_indicators": ["institutions", "total"],
        "failure_indicators": ["INVALID_API_KEYS", "UNAUTHORIZED"],
        "description": "Validates Plaid API secret"
    },
    
    "Loom API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.loom.com/v1/me",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["id", "email"],
        "failure_indicators": ["Unauthorized", "invalid_token"],
        "description": "Validates Loom API token"
    },
    
    "Postman API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.getpostman.com/me",
        "headers": {"X-Api-Key": "{key}"},
        "success_indicators": ["user", "id", "email"],
        "failure_indicators": ["AuthenticationError", "Invalid API Key"],
        "description": "Validates Postman API key"
    },
    
    "Mixpanel API Secret": {
        "type": "http",
        "method": "GET",
        "url": "https://mixpanel.com/api/2.0/engage",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "",
        "success_indicators": ["results", "page"],
        "failure_indicators": ["Invalid secret", "Unauthorized"],
        "description": "Validates Mixpanel API secret"
    },
    
    "Amplitude API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://amplitude.com/api/2/export?start=20200101T00&end=20200101T01",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "{secret}",
        "requires_pair": True,
        "success_indicators": ["events", "data"],
        "failure_indicators": ["Unauthorized", "Invalid credentials"],
        "description": "Validates Amplitude API key and secret"
    },
    
    "Segment Write Key": {
        "type": "http",
        "method": "POST",
        "url": "https://api.segment.io/v1/track",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "",
        "body": '{"userId":"test","event":"test"}',
        "headers": {"Content-Type": "application/json"},
        "success_indicators": ["success"],
        "failure_indicators": ["Invalid write key", "Unauthorized"],
        "description": "Validates Segment write key"
    },
    
    "LaunchDarkly API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://app.launchdarkly.com/api/v2/projects",
        "headers": {"Authorization": "{key}"},
        "success_indicators": ["items", "_links"],
        "failure_indicators": ["Unauthorized", "invalid api key"],
        "description": "Validates LaunchDarkly API access token"
    },
    
    "Intercom Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.intercom.io/me",
        "headers": {"Authorization": "Bearer {key}", "Accept": "application/json"},
        "success_indicators": ["type", "id", "email"],
        "failure_indicators": ["unauthorized", "Invalid token"],
        "description": "Validates Intercom access token"
    },
    
    "Freshdesk API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://{domain}.freshdesk.com/api/v2/tickets?per_page=1",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "X",
        "success_indicators": ["id", "subject"],
        "failure_indicators": ["authentication required", "invalid credentials"],
        "description": "Validates Freshdesk API key"
    },
    
    "Dropbox Access Token": {
        "type": "http",
        "method": "POST",
        "url": "https://api.dropboxapi.com/2/users/get_current_account",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["account_id", "email"],
        "failure_indicators": ["Invalid access token", "expired_access_token"],
        "description": "Validates Dropbox access token"
    },
    
    "Box Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.box.com/2.0/users/me",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["type", "id", "login"],
        "failure_indicators": ["Unauthorized", "expired_token"],
        "description": "Validates Box access token"
    },
    
    "Monday API Token": {
        "type": "http",
        "method": "POST",
        "url": "https://api.monday.com/v2",
        "headers": {"Authorization": "{key}", "Content-Type": "application/json"},
        "body": '{"query":"{ me { id name email } }"}',
        "success_indicators": ["data", "me", "email"],
        "failure_indicators": ["Not Authenticated", "invalid_token"],
        "description": "Validates Monday.com API token"
    },
    
    "ClickUp API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.clickup.com/api/v2/user",
        "headers": {"Authorization": "{key}"},
        "success_indicators": ["user", "id", "email"],
        "failure_indicators": ["OAUTH_017", "Unauthorized"],
        "description": "Validates ClickUp personal API token"
    },
    
    "Trello API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.trello.com/1/members/me?key={key}&token={token}",
        "success_indicators": ["id", "username", "email"],
        "failure_indicators": ["invalid key", "unauthorized"],
        "description": "Validates Trello API key and token"
    },
    
    "Bitly Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api-ssl.bitly.com/v4/user",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["login", "name"],
        "failure_indicators": ["FORBIDDEN", "INVALID_ACCESS_TOKEN"],
        "description": "Validates Bitly access token"
    },
    
    "RapidAPI Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.geoapify.com/v1/ipinfo?apiKey={key}",
        "success_indicators": ["ip", "country"],
        "failure_indicators": ["Invalid API Key", "Unauthorized"],
        "description": "Validates RapidAPI key (via Geoapify)"
    },
    
    "Cohere API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.cohere.ai/v1/models",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["models"],
        "failure_indicators": ["invalid api token", "Unauthorized"],
        "description": "Validates Cohere AI API key"
    },
    
    "Replicate API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.replicate.com/v1/account",
        "headers": {"Authorization": "Token {key}"},
        "success_indicators": ["type", "username"],
        "failure_indicators": ["Unauthorized", "Invalid token"],
        "description": "Validates Replicate API token"
    },
    
    "Pinecone API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.pinecone.io/indexes",
        "headers": {"Api-Key": "{key}"},
        "success_indicators": ["indexes"],
        "failure_indicators": ["Unauthorized", "Invalid API key"],
        "description": "Validates Pinecone API key"
    },
    
    "Weaviate API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://{cluster}.weaviate.network/v1/schema",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["classes"],
        "failure_indicators": ["Unauthorized", "invalid api key"],
        "description": "Validates Weaviate Cloud API key"
    },
}


class KeyHacksValidator:
    """
    Validates discovered secrets using KeyHacks methodology
    
    ⚠️ WARNING: This tool is for AUTHORIZED security testing only.
    Ensure you have explicit permission before validating any secrets.
    """
    
    DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           ⚠️  ETHICAL USE WARNING  ⚠️                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This validation feature is for AUTHORIZED security testing only:           ║
║                                                                              ║
║  ✅ Bug Bounty Programs (with explicit scope permission)                     ║
║  ✅ Authorized Penetration Testing                                           ║
║  ✅ Security Assessments (with signed authorization)                         ║
║                                                                              ║
║  ❌ Unauthorized access to systems is ILLEGAL                                ║
║  ❌ Using validated keys without permission is a CRIME                       ║
║                                                                              ║
║  🔒 I am just a tool. Always verify findings manually.                       ║
║  🔒 Confirm authorization before reporting or using validated secrets.      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.verify_ssl = verify_ssl
        self.validated_count = 0
        self.valid_secrets = []
    
    def print_disclaimer(self):
        """Print ethical use disclaimer"""
        console.print(self.DISCLAIMER, style="bold yellow")
    
    def get_validator(self, pattern_name: str) -> Optional[Dict]:
        """Get validation config for a pattern"""
        # Try exact match
        if pattern_name in KEYHACKS_VALIDATORS:
            return KEYHACKS_VALIDATORS[pattern_name]
        
        # Try partial match
        for key in KEYHACKS_VALIDATORS:
            if key.lower() in pattern_name.lower() or pattern_name.lower() in key.lower():
                return KEYHACKS_VALIDATORS[key]
        
        return None
    
    async def validate_http(self, validator: Dict, secret: str, extra_params: Dict = None) -> ValidationResult:
        """Validate secret using HTTP request"""
        try:
            url = validator["url"].format(key=secret, **(extra_params or {}))
            method = validator.get("method", "GET").upper()
            headers = {}
            
            # Build headers
            if "headers" in validator:
                for k, v in validator["headers"].items():
                    headers[k] = v.format(key=secret, **(extra_params or {}))
            
            # Build auth
            auth = None
            if validator.get("auth") == "basic":
                auth_user = validator.get("auth_user", "").format(key=secret, **(extra_params or {}))
                auth_pass = validator.get("auth_pass", "").format(key=secret, **(extra_params or {}))
                auth = aiohttp.BasicAuth(auth_user, auth_pass)
            
            # Build body
            body = None
            if "body" in validator:
                body = validator["body"].format(key=secret, **(extra_params or {}))
            
            # Build data
            data = None
            if "data" in validator:
                data = {k: v.format(key=secret) for k, v in validator["data"].items()}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                if method == "GET":
                    async with session.get(url, headers=headers, auth=auth, ssl=self.verify_ssl) as resp:
                        response_text = await resp.text()
                        return self._analyze_response(validator, response_text, resp.status, url)
                elif method == "POST":
                    async with session.post(url, headers=headers, auth=auth, data=body or data, ssl=self.verify_ssl) as resp:
                        response_text = await resp.text()
                        return self._analyze_response(validator, response_text, resp.status, url)
        
        except asyncio.TimeoutError:
            return ValidationResult(
                status=ValidationStatus.UNKNOWN,
                message="Request timed out",
                validation_command=f"curl -X {method} '{url}'"
            )
        except Exception as e:
            return ValidationResult(
                status=ValidationStatus.ERROR,
                message=f"Validation error: {str(e)[:100]}",
                validation_command=f"curl -X {method} '{url}'"
            )
    
    def _analyze_response(self, validator: Dict, response: str, status_code: int, url: str) -> ValidationResult:
        """Analyze HTTP response to determine validity"""
        response_lower = response.lower()
        
        # Check for success indicators
        success_count = 0
        for indicator in validator.get("success_indicators", []):
            if indicator.lower() in response_lower:
                success_count += 1
        
        # Check for failure indicators
        failure_count = 0
        for indicator in validator.get("failure_indicators", []):
            if indicator.lower() in response_lower:
                failure_count += 1
        
        # Determine status
        if failure_count > 0:
            return ValidationResult(
                status=ValidationStatus.INVALID,
                message=f"Key appears to be invalid (HTTP {status_code})",
                raw_response=response[:500],
                validation_command=f"Manual: curl '{url}'"
            )
        elif success_count >= 2 or (success_count > 0 and status_code == 200):
            return ValidationResult(
                status=ValidationStatus.VALID,
                message=f"✅ KEY IS VALID! (HTTP {status_code}, {success_count} success indicators)",
                raw_response=response[:500],
                validation_command=f"curl '{url}'"
            )
        elif status_code == 429:
            return ValidationResult(
                status=ValidationStatus.RATE_LIMITED,
                message="Rate limited - try manual validation",
                validation_command=f"curl '{url}'"
            )
        elif status_code in [401, 403]:
            return ValidationResult(
                status=ValidationStatus.INVALID,
                message=f"Authentication failed (HTTP {status_code})",
                validation_command=f"curl '{url}'"
            )
        else:
            return ValidationResult(
                status=ValidationStatus.UNKNOWN,
                message=f"Unclear result (HTTP {status_code}) - verify manually",
                raw_response=response[:300],
                validation_command=f"curl '{url}'"
            )
    
    async def validate_secret(self, pattern_name: str, secret_value: str, extra_params: Dict = None) -> ValidationResult:
        """
        Validate a discovered secret
        
        Args:
            pattern_name: The type of secret (e.g., "GitHub PAT")
            secret_value: The actual secret value
            extra_params: Additional parameters needed for validation
        
        Returns:
            ValidationResult with status and details
        """
        validator = self.get_validator(pattern_name)
        
        if not validator:
            return ValidationResult(
                status=ValidationStatus.UNKNOWN,
                message=f"No validator available for {pattern_name}. Manual verification required.",
                validation_command="N/A - Check KeyHacks for manual validation"
            )
        
        # Check if requires pair (like AWS key + secret)
        if validator.get("requires_pair"):
            if not extra_params or "secret" not in extra_params:
                return ValidationResult(
                    status=ValidationStatus.UNKNOWN,
                    message=f"Requires paired secret ({validator.get('pair_pattern', 'secret')}). Cannot validate alone.",
                    validation_command=validator.get("description", "Manual validation required")
                )
        
        # Validate based on type
        if validator.get("type") == "http":
            result = await self.validate_http(validator, secret_value, extra_params)
        elif validator.get("type") == "command":
            result = ValidationResult(
                status=ValidationStatus.UNKNOWN,
                message="Command-based validation not auto-run for safety. Use manual command.",
                validation_command=validator["command"].format(key=secret_value, **(extra_params or {}))
            )
        else:
            result = ValidationResult(
                status=ValidationStatus.UNKNOWN,
                message="Unknown validator type"
            )
        
        # Track valid secrets
        if result.status == ValidationStatus.VALID:
            self.validated_count += 1
            self.valid_secrets.append({
                "pattern": pattern_name,
                "value": secret_value[:20] + "...",
                "message": result.message
            })
        
        return result
    
    def get_manual_verification_note(self) -> str:
        """Get manual verification note for reports"""
        return """
┌─────────────────────────────────────────────────────────────────────────────┐
│                        📋 MANUAL VERIFICATION REQUIRED                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  This tool provides AUTOMATED validation which may have false positives    │
│  or false negatives. Before reporting:                                     │
│                                                                             │
│  1. ✅ Verify the secret is actually valid using the provided commands     │
│  2. ✅ Confirm the secret belongs to the target organization               │
│  3. ✅ Check if the secret has any actual permissions/access               │
│  4. ✅ Document the exact steps to reproduce                               │
│  5. ✅ Ensure you have authorization to test                               │
│                                                                             │
│  💡 Use the curl commands provided to manually verify each finding.        │
│                                                                             │
│  ⚠️  I am just a tool. The final verification is YOUR responsibility.      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
"""


# Convenience function for quick validation
async def validate_key(pattern_name: str, secret_value: str) -> ValidationResult:
    """Quick validation of a single key"""
    validator = KeyHacksValidator()
    return await validator.validate_secret(pattern_name, secret_value)
