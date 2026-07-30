#!/usr/bin/env python
# SecretFinder - Tool for discover apikeys/accesstokens and sensitive data in js file
# based on LinkFinder - github.com/GerbenJavado
# By m4ll0k (@m4ll0k2) github.com/m4ll0k


import os,sys
if not sys.version_info.major >= 3:
    print("[ + ] Run this tool with python version 3.+")
    sys.exit(0)
os.environ["BROWSER"] = "open"

import re
import glob
import argparse
import jsbeautifier
import webbrowser
import subprocess
import base64
import requests
import string
import random
from html import escape
import urllib3
import xml.etree.ElementTree

# disable warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# for read local file with file:// protocol
from requests_file import FileAdapter
from lxml import html
from urllib.parse import urlparse

# regex
_regex = {
    # --- 1. GRUP: SİZİN MEVCUT VE DÜZELTİLMİŞ PATTERNLERİNİZ ---
    'google_api'                    : r'AIza[0-9A-Za-z-_]{35}',
    'firebase'                      : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha'                : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'                  : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id'      : r'\b((?:AKIA|ASIA)[A-Z0-9]{16})\b',
    'amazon_mws_auth_toke'          : r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url'                : r's3\.amazonaws\.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com',
    'amazon_aws_url2'               : (r"([a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com"
                                       r"|s3://[a-zA-Z0-9-\.\_]+"
                                       r"|s3-[a-zA-Z0-9-\.\_\/]+"
                                       r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+"
                                       r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)"),
    'facebook_access_token'         : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic'           : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer'          : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',

    # KESİN HATA DÜZELTİLDİ: Karakter sınıfı [key|...] yerine non-capturing group (?:...) getirildi.
    'authorization_api'             : r'(?i)api(?:_?key|pass|\s+)+[a-zA-Z0-9_\-]{5,100}',

    'mailgun_api_key'               : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key'                : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid'            : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid'                : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret'           : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token'           : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api'           : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api'         : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token'           : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*', # Tarih oldu ama arkada dursun
    'rsa_private_key'               : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key'           : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key'            : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block'             : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token'                : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$', # Post-process şart!
    'slack_token'                   : r"xox[a-zA-Z]-[a-zA-Z0-9-]+",
    'SSH_privKey'                   : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY'                : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds'                : r"(?i)(password\s*[`=:\"]+\s*[^\s]+|password is\s*[`=:\"]*\s*[^\s]+|pwd\s*[`=:\"]*\s*[^\s]+|passwd\s*[`=:\"]+\s*[^\s]+)",

    # --- 2. GRUP: DÜZELTİLMİŞ VE PARLATILMIŞ ENTEGRE PATTERNLER ---
    '1password_secret_key'          : r'\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b',
    '1password_service_account'     : r'ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}',
    'adafruit_api_key'              : r'(?i)[\w.-]{0,50}?(?:adafruit)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9_-]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'adobe_client_id'               : r'(?i)[\w.-]{0,50}?(?:adobe)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'adobe_client_secret'           : r'(?i)\b(p8e-[a-z0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'age_secret_key'                : r'AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}',
    'airtable_api_key'              : r'(?i)[\w.-]{0,50}?(?:airtable)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{17})(?:[\x60\'"\s;]|\\[nr]|$)',
    'airtable_personal_access_token': r'\b(pat[a-zA-Z0-9]{14}\.[a-f0-9]{64})\b',
    'algolia_api_key'               : r'(?i)[\w.-]{0,50}?(?:algolia)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'alibaba_access_key_id'         : r'(?i)\b(LTAI[a-z0-9]{20})(?:[\x60\'"\s;]|\\[nr]|$)',
    'alibaba_secret_key'            : r'(?i)[\w.-]{0,50}?(?:alibaba)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{30})(?:[\x60\'"\s;]|\\[nr]|$)',
    'anthropic_admin_api_key'       : r'\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:[\x60\'"\s;]|\\[nr]|$)',
    'anthropic_api_key'             : r'\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:[\x60\'"\s;]|\\[nr]|$)',
    'artifactory_api_key'           : r'\bAKCp[A-Za-z0-9]{69}\b',
    'artifactory_reference_token'   : r'\bcmVmd[A-Za-z0-9]{59}\b',
    'asana_client_id'               : r'(?i)[\w.-]{0,50}?(?:asana)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9]{16})(?:[\x60\'"\s;]|\\[nr]|$)',
    'asana_client_secret'           : r'(?i)[\w.-]{0,50}?(?:asana)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',

    # MANTIKSAL DÜZELTME: (?i) varken küçük harf kalabalığı (`atlassian`, `jira` vb.) temizlendi.
    'atlassian_api_token'           : r'(?i)[\w.-]{0,50}?(?:ATLASSIAN|CONFLUENCE|JIRA)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{20}[a-f0-9]{4})(?:[\x60\'"\s;]|\\[nr]|$)|\b(ATATT3[A-Za-z0-9_\-=]{186})(?:[\x60\'"\s;]|\\[nr]|$)',

    'authress_service_client_key'   : r'(?i)\b((?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})(?:[\x60\'"\s;]|\\[nr]|$)',
    'aws_access_token'              : r'\b((?:AKIA|ASIA)[A-Z0-9]{16})\b', # DÜZELTİLDİ: Uçabilecek sahte AWS varyasyonları elendi.
    'aws_bedrock_key_long_lived'    : r'\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\x60\'"\s;]|\\[nr]|$)',
    'aws_bedrock_key_short_lived'   : r'bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t',
    'azure_ad_client_secret'        : r'(?:^|[\\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\\'"\x60\s<),])',
    'beamer_api_token'              : r'(?i)[\w.-]{0,50}?(?:beamer)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(b_[a-z0-9=_\-]{44})(?:[\x60\'"\s;]|\\[nr]|$)',
    'bitbucket_client_id'           : r'(?i)[\w.-]{0,50}?(?:bitbucket)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'bitbucket_client_secret'       : r'(?i)[\w.-]{0,50}?(?:bitbucket)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{64})(?:[\x60\'"\s;]|\\[nr]|$)',
    'bittrex_access_key'            : r'(?i)[\w.-]{0,50}?(?:bittrex)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'bittrex_secret_key'            : r'(?i)[\w.-]{0,50}?(?:bittrex)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'cisco_meraki_api_key'          : r'(?i)[\w.-]{0,50}?(?:[\w.-]{0,50}?(?:meraki)(?:[ \t\w.-]{0,20})[\s\'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9a-f]{40})(?:[\x60\'"\s;]|\\[nr]|$)',
    'clickhouse_cloud_secret_key'   : r'\b(4b1d[A-Za-z0-9]{38})\b',
    'clojars_api_token'              : r'(?i)CLOJARS_[a-z0-9]{60}',
    'cloudflare_api_key'            : r'(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9_-]{40})(?:[\x60\'"\s;]|\\[nr]|$)',
    'cloudflare_global_api_key'      : r'(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{37})(?:[\x60\'"\s;]|\\[nr]|$)',
    'cloudflare_origin_ca_key'       : r'\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\x60\'"\s;]|\\[nr]|$)',
    'codecov_access_token'          : r'(?i)[\w.-]{0,50}?(?:codecov)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'cohere_api_token'              : r'(?i)[\w.-]{0,50}?(?:[\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \t\w.-]{0,20})[\s\'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-zA-Z0-9]{40})(?:[\x60\'"\s;]|\\[nr]|$)',
    'coinbase-access-token'         : r'(?i)[\w.-]{0,50}?(?:coinbase)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9_-]{64})(?:[\x60\'"\s;]|\\[nr]|$)',
    'confluent_access_token'        : r'(?i)[\w.-]{0,50}?(?:confluent)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{16})(?:[\x60\'"\s;]|\\[nr]|$)',
    'confluent_secret_key'          : r'(?i)[\w.-]{0,50}?(?:confluent)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{64})(?:[\x60\'"\s;]|\\[nr]|$)',
    'contentful_delivery_api_token' : r'(?i)[\w.-]{0,50}?(?:contentful)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{43})(?:[\x60\'"\s;]|\\[nr]|$)',
    'curl_auth_header'              : r'(?i)\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:"(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))"|\'(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))\')(?:\B|\s|\Z)',

    # MANTIKSAL DÜZELTME: Kırpılmış `(?:...)` faciası yerine Gitleaks'in orijinal tam curl regex'i getirildi.
    'curl_auth_user'                : r'(?i)\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})(?:"([^"|:]+):([^"]+)"|\'([^\'|:]+):([^\']+)\')(?:\B|\s|\Z)',

    'databricks_api_token'          : r'\b(dapi[a-f0-9]{32}(?:-\d)?)(?:[\x60\'"\s;]|\\[nr]|$)',
    'datadog_access_token'          : r'(?i)[\w.-]{0,50}?(?:datadog)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{40})(?:[\x60\'"\s;]|\\[nr]|$)',
    'defined_networking_api_token'  : r'(?i)[\w.-]{0,50}?(?:dnkey)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})(?:[\x60\'"\s;]|\\[nr]|$)',
    'digitalocean_access_token'     : r'\b(doo_v1_[a-f0-9]{64})(?:[\x60\'"\s;]|\\[nr]|$)',
    'digitalocean_pat'              : r'\b(dop_v1_[a-f0-9]{64})(?:[\x60\'"\s;]|\\[nr]|$)',
    'digitalocean_refresh_token'    : r'(?i)\b(dor_v1_[a-f0-9]{64})(?:[\x60\'"\s;]|\\[nr]|$)',
    'discord_api_token'             : r'(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{64})(?:[\x60\'"\s;]|\\[nr]|$)',
    'discord_client_id'             : r'(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9]{18})(?:[\x60\'"\s;]|\\[nr]|$)',
    'discord_client_secret'         : r'(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'doppler_api_token'             : r'(?i)dp\.pt\.[a-z0-9]{43}',
    'droneci_access_token'          : r'(?i)[\w.-]{0,50}?(?:droneci)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'dropbox_api_token'             : r'(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{15})(?:[\x60\'"\s;]|\\[nr]|$)',
    'dropbox_long_lived_token'      : r'(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43})(?:[\x60\'"\s;]|\\[nr]|$)',
    'dropbox_short_lived_token'     : r'(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(sl\.[a-z0-9\-=_]{135})(?:[\x60\'"\s;]|\\[nr]|$)',
    'duffel_api_token'              : r'(?i)duffel_(?:test|live)_[a-z0-9_\-=]{43}',
    'dynatrace_api_token'           : r'(?i)dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}',
    'easypost_api_token'            : r'(?i)\bEZAK[a-z0-9]{54}\b',
    'easypost_test_api_token'       : r'(?i)\bEZTK[a-z0-9]{54}\b',
    'etsy_access_token'             : r'(?i)[\w.-]{0,50}?(?:ETSY|etsy)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{24})(?:[\x60\'"\s;]|\\[nr]|$)',
    'facebook_page_access_token'    : r'(?i)\b(EAA[MC][a-z0-9]{100,})(?:[\x60\'"\s;]|\\[nr]|$)',
    'facebook_secret'               : r'(?i)[\w.-]{0,50}?(?:facebook)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'fastly_api_token'              : r'(?i)[\w.-]{0,50}?(?:fastly)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'finicity_api_token'            : r'(?i)[\w.-]{0,50}?(?:finicity)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'finicity_client_secret'        : r'(?i)[\w.-]{0,50}?(?:finicity)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{20})(?:[\x60\'"\s;]|\\[nr]|$)',
    'finnhub_access_token'          : r'(?i)[\w.-]{0,50}?(?:finnhub)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{20})(?:[\x60\'"\s;]|\\[nr]|$)',
    'flickr_access_token'           : r'(?i)[\w.-]{0,50}?(?:flickr)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'flutterwave_encryption_key'    : r'(?i)FLWSECK_TEST-[a-h0-9]{12}',
    'flutterwave_public_key'        : r'(?i)FLWPUBK_TEST-[a-h0-9]{32}-X',
    'flutterwave_secret_key'        : r'(?i)FLWSECK_TEST-[a-h0-9]{32}-X',
    'flyio_access_token'            : r'\b((?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\/]{100,}={0,3}))(?:[\x60\'"\s;]|\\[nr]|$)',
    'frameio_api_token'             : r'(?i)fio-u-[a-z0-9\-_=]{64}',
    'freemius_secret_key'           : r'(?i)["\']secret_key["\']\s*=>\s*["\'](sk_[\S]{29})["\']',
    'freshbooks_access_token'       : r'(?i)[\w.-]{0,50}?(?:freshbooks)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{64})(?:[\x60\'"\s;]|\\[nr]|$)',

    # MANTIKSAL DÜZELTME: False positive'leri engellemek için yakalanan değerin minimum karakter sınırı 16'ya yükseltildi.
    'generic_api_key'               : r'(?i)[\w.-]{0,50}?(?:access|auth|api|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([\w.=-]{16,150}|[a-z0-9][a-z0-9+/]{15,}={0,3})(?:[\x60\'"\s;]|\\[nr]|$)',

    'github_app_token'              : r'(?:ghu|ghs)_[0-9a-zA-Z]{36}',
    'github_fine_grained_pat'       : r'github_pat_\w{82}',
    'github_oauth'                  : r'gho_[0-9a-zA-Z]{36}',
    'github_pat'                    : r'ghp_[0-9a-zA-Z]{36}',
    'github_refresh_token'          : r'ghr_[0-9a-zA-Z]{36}',
    'gitlab_cicd_job_token'         : r'glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}',
    'gitlab_deploy_token'           : r'gldt-[0-9a-zA-Z_\-]{20}',
    'gitlab_feature_flag_client'    : r'glffct-[0-9a-zA-Z_\-]{20}',
    'gitlab_feed_token'             : r'glft-[0-9a-zA-Z_\-]{20}',
    'gitlab_incoming_mail_token'    : r'glimt-[0-9a-zA-Z_\-]{25}',
    'gitlab_kubernetes_agent_token' : r'glagent-[0-9a-zA-Z_\-]{50}',
    'gitlab_oauth_app_secret'       : r'gloas-[0-9a-zA-Z_\-]{64}',
    'gitlab_pat'                    : r'glpat-[\w-]{20}',
    'gitlab_pat_routable'           : r'\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b',
    'gitlab_ptt'                    : r'glptt-[0-9a-f]{40}',
    'gitlab_rrt'                    : r'GR1348941[\w-]{20}',
    'gitlab_runner_auth_token'      : r'glrt-[0-9a-zA-Z_\-]{20}',
    'gitlab_runner_auth_routable'   : r'\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b',
    'gitlab_scim_token'             : r'glsoat-[0-9a-zA-Z_\-]{20}',
    'gitlab_session_cookie'         : r'_gitlab_session=[0-9a-z]{32}',
    'gitter_access_token'           : r'(?i)[\w.-]{0,50}?(?:gitter)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9_-]{40})(?:[\x60\'"\s;]|\\[nr]|$)',
    'gocardless_api_token'          : r'(?i)[\w.-]{0,50}?(?:gocardless)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(live_[a-z0-9\-_=]{40})(?:[\x60\'"\s;]|\\[nr]|$)',
    'grafana_api_key'               : r'(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\x60\'"\s;]|\\[nr]|$)',
    'grafana_cloud_api_token'       : r'(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\x60\'"\s;]|\\[nr]|$)',
    'grafana_service_account_token' : r'(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\x60\'"\s;]|\\[nr]|$)',
    'harness_api_key'               : r'(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}',
    'hashicorp_tf_api_token'        : r'(?i)[a-z0-9]{14}\.(?:atlasv1|ATLASV1)\.[a-z0-9\-_=]{60,70}',
    'hashicorp_tf_password'         : r'(?i)[\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}("[a-z0-9=_\-]{8,20}")(?:[\x60\'"\s;]|\\[nr]|$)',
    'heroku_api_key_v2'             : r'\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\x60\'"\s;]|\\[nr]|$)',
    'hubspot_api_key'               : r'(?i)[\w.-]{0,50}?(?:hubspot)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\x60\'"\s;]|\\[nr]|$)',
    'huggingface_access_token'      : r'(?i)\b(hf_[a-z]{34})(?:[\x60\'"\s;]|\\[nr]|$)',
    'huggingface_org_api_token'     : r'(?i)\b(api_org_[a-z]{34})(?:[\x60\'"\s;]|\\[nr]|$)',
    'infracost_api_token'           : r'\b(ico-[a-zA-Z0-9]{32})(?:[\x60\'"\s;]|\\[nr]|$)',
    'intercom_api_key'              : r'(?i)[\w.-]{0,50}?(?:intercom)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{60})(?:[\x60\'"\s;]|\\[nr]|$)',
    'intra42_client_secret'         : r'(?i)\b(s-s4t2(?:ud|af)-[abcdef0123456789]{64})(?:[\x60\'"\s;]|\\[nr]|$)',
    'jfrog_api_key'                 : r'(?i)[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{73})(?:[\x60\'"\s;]|\\[nr]|$)',
    'jfrog_identity_token'          : r'(?i)[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{64})(?:[\x60\'"\s;]|\\[nr]|$)',
    'jwt_another_pattern'           : r'\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:[\x60\'"\s;]|\\[nr]|$)',
    'jwt_base64'                    : r'\bZXlK(?:(?P<alg>aGJHY2lPaU)|(?P<apu>aGNIVWlPaU)|(?P<apv>aGNIWWlPaU)|(?P<aud>aGRXUWlPaU)|(?P<b64>aU5qUWlP)|(?P<crit>amNtbDBJanBi)|(?P<cty>amRIa2lPaU)|(?P<epk>bGNHc2lPbn)|(?P<enc>bGJtTWlPaU)|(?P<jku>cWEzVWlPaU)|(?P<jwk>cWQyc2lPb)|(?P<iss>cGMzTWlPaU)|(?P<iv>cGRpSTZJ)|(?P<kid>cmFXUWlP)|(?P<key_ops>clpYbGZiM0J6SWpwY)|(?P<kty>cmRIa2lPaUp)|(?P<nonce>dWIyNWpaU0k2)|(?P<p2c>d01tTWlP)|(?P<p2s>d01uTWlPaU)|(?P<ppt>d2NIUWlPaU)|(?P<sub>emRXSWlPaU)|(?P<svt>emRuUWlP)|(?P<tag>MFlXY2lPaU)|(?P<typ>MGVYQWlPaUp)|(?P<url>MWNtd2l)|(?P<use>MWMyVWlPaUp)|(?P<ver>MlpYSWlPaU)|(?P<version>MlpYSnphVzl1SWpv)|(?P<x>NElqb2)|(?P<x5c>NE5XTWlP)|(?P<x5t>NE5YUWlPaU)|(?P<x5ts256>NE5YUWpVekkxTmlJNkl)|(?P<x5u>NE5YVWlPaU)|(?P<zip>NmFYQWlPaU))[a-zA-Z0-9\/\\_+\-\r\n]{40,}={0,2}',
    'kraken_access_token'           : r'(?i)[\w.-]{0,50}?(?:kraken)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9\/=_\+\-]{80,90})(?:[\x60\'"\s;]|\\[nr]|$)',
    'kucoin_access_token'           : r'(?i)[\w.-]{0,50}?(?:kucoin)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{24})(?:[\x60\'"\s;]|\\[nr]|$)',
    'kucoin_secret_key'             : r'(?i)[\w.-]{0,50}?(?:kucoin)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60\'"\s;]|\\[nr]|$)',
    'launchdarkly_access_token'     : r'(?i)[\w.-]{0,50}?(?:launchdarkly)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{40})(?:[\x60\'"\s;]|\\[nr]|$)',
    'linear_api_key'                : r'(?i)lin_api_[a-z0-9]{40}',
    'openai_api_key'          : r'sk-proj-[A-Za-z0-9_-]{20,}',
    'openai_legacy_key'       : r'sk-[A-Za-z0-9]{40,}',
    'anthropic_api_key_short' : r'sk-ant-[A-Za-z0-9_-]{20,}',
    'groq_api_key'            : r'gsk_[A-Za-z0-9]{40,}',
    'resend_api_key'          : r're_[A-Za-z0-9]{20,}',
    'clerk_secret_key'        : r'sk_(?:test|live)_[A-Za-z0-9]{20,}',
    'supabase_anon_key'       : r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    'vercel_token'            : r'\b(?:vercel|vcs)_[A-Za-z0-9]{24,}\b',
    'github_pat_new'          : r'github_pat_[A-Za-z0-9_]{80,}',
    'npm_token'              : r'npm_[A-Za-z0-9]{36}',
    'pnpm_token'             : r'pnpm_[A-Za-z0-9]{20,}',
    'slack_bot_token'        : r'xoxb-[0-9A-Za-z-]{20,}',
    'slack_user_token'       : r'xoxp-[0-9A-Za-z-]{20,}',
    'stripe_webhook_secret'  : r'whsec_[A-Za-z0-9]{20,}',
    'sentry_auth_token'      : r'sntrys_[A-Za-z0-9]{20,}',
    'kubernetes_secret_yaml'        : r"""(?i)(?:\bkind:[ \t]*["']?\bsecret\b["']?(?s:.){0,200}?\bdata:(?s:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+}}|""|''))|\bdata:(?s:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+}}|""|''))(?s:.){0,200}?\bkind:[ \t]*["']?\bsecret\b["']?)""",
}

_template = '''
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
       h1 {
          font-family: sans-serif;
       }
       a {
          color: #000;
       }
       .text {
          font-size: 16px;
          font-family: Helvetica, sans-serif;
          color: #323232;
          background-color: white;
       }
       .container {
          background-color: #e9e9e9;
          padding: 10px;
          margin: 10px 0;
          font-family: helvetica;
          font-size: 13px;
          border-width: 1px;
          border-style: solid;
          border-color: #8a8a8a;
          color: #323232;
          margin-bottom: 15px;
       }
       .button {
          padding: 17px 60px;
          margin: 10px 10px 10px 0;
          display: inline-block;
          background-color: #f4f4f4;
          border-radius: .25rem;
          text-decoration: none;
          -webkit-transition: .15s ease-in-out;
          transition: .15s ease-in-out;
          color: #333;
          position: relative;
       }
       .button:hover {
          background-color: #eee;
          text-decoration: none;
       }
       .github-icon {
          line-height: 0;
          position: absolute;
          top: 14px;
          left: 24px;
          opacity: 0.7;
       }
  </style>
  <title>LinkFinder Output</title>
</head>
<body contenteditable="true">
  $$content$$

  <a class='button' contenteditable='false' href='https://github.com/m4ll0k/SecretFinder/issues/new' rel='nofollow noopener noreferrer' target='_blank'><span class='github-icon'><svg height="24" viewbox="0 0 24 24" width="24" xmlns="http://www.w3.org/2000/svg">
  <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" fill="none" stroke="#000" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"></path></svg></span> Report an issue.</a>
</body>
</html>
'''

def parser_error(msg):
    print('Usage: python %s [OPTIONS] use -h for help'%sys.argv[0])
    print('Error: %s'%msg)
    sys.exit(0)

def getContext(matches,content,name,rex='.+?'):
    ''' get context '''
    items = []
    matches2 =  []
    for  i in [x[0] for x in matches]:
        if i not in matches2:
            matches2.append(i)
    for m in matches2:
        context = re.findall('%s%s%s' % (rex, re.escape(m), rex),content,re.IGNORECASE)

        item = {
            'matched'          : m,
            'name'             : name,
            'context'          : context,
            'multi_context'    : True if len(context) > 1 else False
        }
        items.append(item)
    return items


def parser_file(content,mode=1,more_regex=None,no_dup=1):
    ''' parser file '''
    if mode == 1:
        if len(content) > 1000000:
            content = content.replace(";",";\r\n").replace(",",",\r\n")
        else:
            content = jsbeautifier.beautify(content)
    all_items = []
    for regex in _regex.items():
        r = re.compile(regex[1],re.VERBOSE|re.I)
        if mode == 1:
            all_matches = [(m.group(0),m.start(0),m.end(0)) for m in re.finditer(r,content)]
            items = getContext(all_matches,content,regex[0])
            if items != []:
                all_items.append(items)
        else:
            items = [{
                'matched' : m.group(0),
                'context' : [],
                'name'    : regex[0],
                'multi_context' : False
            } for m in re.finditer(r,content)]
        if items != []:
            all_items.append(items)
    if all_items != []:
        k = []
        for i in range(len(all_items)):
            for ii in all_items[i]:
                if ii not in k:
                    k.append(ii)
        if k != []:
            all_items = k

    if no_dup:
        all_matched = set()
        no_dup_items = []
        for item in all_items:
            if item != [] and type(item) is dict:
                if item['matched'] not in all_matched:
                    all_matched.add(item['matched'])
                    no_dup_items.append(item)
        all_items = no_dup_items

    filtered_items = []
    if all_items != []:
        for item in all_items:
            if more_regex:
                if re.search(more_regex,item['matched']):
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
    return filtered_items


def parser_input(input):
    ''' Parser Input '''
    # method 1 - url
    schemes = ('http://','https://','ftp://','file://','ftps://')
    if input.startswith(schemes):
        return [input]
    # method 2 - url inpector firefox/chrome
    if input.startswith('view-source:'):
        return [input[12:]]
    # method 3 - Burp file
    if args.burp:
        jsfiles = []
        items = []

        try:
            items = xml.etree.ElementTree.fromstring(open(args.input,'r').read())
        except Exception as err:
            print(err)
            sys.exit()
        for item in items:
            jsfiles.append(
                {
                    'js': base64.b64decode(item.find('response').text).decode('utf-8','replace'),
                    'url': item.find('url').text
                }
            )
        return jsfiles
    # method 4 - folder with a wildcard
    if '*' in input:
        paths = glob.glob(os.path.abspath(input))
        for index, path in enumerate(paths):
            paths[index] = "file://%s" % path
        return (paths if len(paths)> 0 else parser_error('Input with wildcard does not match any files.'))

    # method 5 - local file
    path = "file://%s"% os.path.abspath(input)
    return [path if os.path.exists(input) else parser_error('file could not be found (maybe you forgot to add http/https).')]


def html_save(output):
    ''' html output '''
    hide = os.dup(1)
    os.close(1)
    os.open(os.devnull,os.O_RDWR)
    try:
        text_file = open(args.output,"wb")
        text_file.write(_template.replace('$$content$$',output).encode('utf-8'))
        text_file.close()

        print('URL to access output: file://%s'%os.path.abspath(args.output))
        file = 'file:///%s'%(os.path.abspath(args.output))
        if sys.platform == 'linux' or sys.platform == 'linux2':
            subprocess.call(['xdg-open',file])
        else:
            webbrowser.open(file)
    except Exception as err:
        print('Output can\'t be saved in %s due to exception: %s'%(args.output,err))
    finally:
        os.dup2(hide,1)

def cli_output(matched):
    ''' cli output '''
    for match in matched:
        print(match.get('name')+'\t->\t'+match.get('matched').encode('ascii','ignore').decode('utf-8'))

def urlParser(url):
    ''' urlParser '''
    parse = urlparse(url)
    urlParser.this_root = parse.scheme + '://' + parse.netloc
    urlParser.this_path = parse.scheme + '://' + parse.netloc  + '/' + parse.path

def extractjsurl(content,base_url):
    ''' JS url extract from html page '''
    soup = html.fromstring(content)
    all_src = []
    urlParser(base_url)
    for src in soup.xpath('//script'):
        src = src.xpath('@src')[0] if src.xpath('@src') != [] else []
        if src != []:
            if src.startswith(('http://','https://','ftp://','ftps://')):
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('//'):
                src = 'http://'+src[2:]
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('/'):
                src = urlParser.this_root + src
                if src not in all_src:
                    all_src.append(src)
            else:
                src = urlParser.this_path + src
                if src not in all_src:
                    all_src.append(src)
    if args.ignore and all_src != []:
        temp = all_src
        ignore = []
        for i in args.ignore.split(';'):
            for src in all_src:
                if i in src:
                    ignore.append(src)
        if ignore:
            for i in ignore:
                temp.pop(int(temp.index(i)))
        return temp
    if args.only:
        temp = all_src
        only = []
        for i in args.only.split(';'):
            for src in all_src:
                if i in src:
                    only.append(src)
        return only
    return all_src

def send_request(url):
    ''' Send Request '''
    # read local file
    # https://github.com/dashea/requests-file
    if 'file://' in url:
        s = requests.Session()
        s.mount('file://',FileAdapter())
        return s.get(url).content.decode('utf-8','replace')
    # set headers and cookies
    headers = {}
    default_headers = {
        'User-Agent'      : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'Accept'          : 'text/html, application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language' : 'en-US,en;q=0.8',
        'Accept-Encoding' : 'gzip'
    }
    if args.headers:
        for i in args.header.split('\\n'):
            # replace space and split
            name,value = i.replace(' ','').split(':')
            headers[name] = value
    # add cookies
    if args.cookie:
        headers['Cookie'] = args.cookie

    headers.update(default_headers)
    # proxy
    proxies = {}
    if args.proxy:
        proxies.update({
            'http'  : args.proxy,
            'https' : args.proxy,
            # ftp
        })
    try:
        resp = requests.get(
            url = url,
            verify = False,
            headers = headers,
            proxies = proxies
        )
        return resp.content.decode('utf-8','replace')
    except Exception as err:
        print(err)
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-e","--extract",help="Extract all javascript links located in a page and process it",action="store_true",default=False)
    parser.add_argument("-i","--input",help="Input a: URL, file or folder",required="True",action="store")
    parser.add_argument("-o","--output",help="Where to save the file, including file name. Default: output.html",action="store", default="output.html")
    parser.add_argument("-r","--regex",help="RegEx for filtering purposes against found endpoint (e.g: ^/api/)",action="store")
    parser.add_argument("-b","--burp",help="Support burp exported file",action="store_true")
    parser.add_argument("-c","--cookie",help="Add cookies for authenticated JS files",action="store",default="")
    parser.add_argument("-g","--ignore",help="Ignore js url, if it contain the provided string (string;string2..)",action="store",default="")
    parser.add_argument("-n","--only",help="Process js url, if it contain the provided string (string;string2..)",action="store",default="")
    parser.add_argument("-H","--headers",help="Set headers (\"Name:Value\\nName:Value\")",action="store",default="")
    parser.add_argument("-p","--proxy",help="Set proxy (host:port)",action="store",default="")
    args = parser.parse_args()

    if args.input[-1:] == "/":
        # /aa/ -> /aa
        args.input = args.input[:-1]

    mode = 1
    if args.output == "cli":
        mode = 0
    # add args
    if args.regex:
        # validate regular exp
        try:
            r = re.search(args.regex,''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(10,50))))
        except Exception as e:
            print('your python regex isn\'t valid')
            sys.exit()

        _regex.update({
            'custom_regex' : args.regex
        })

    if args.extract:
        content = send_request(args.input)
        urls = extractjsurl(content,args.input)
    else:
        # convert input to URLs or JS files
        urls = parser_input(args.input)
    # conver URLs to js file
    output = ''
    for url in urls:
        print('[ + ] URL: '+url)
        if not args.burp:
            file = send_request(url)
        else:
            file = url.get('js')
            url = url.get('url')

        matched = parser_file(file,mode)
        if args.output == 'cli':
            cli_output(matched)
        else:
            output += '<h1>File: <a href="%s" target="_blank" rel="nofollow noopener noreferrer">%s</a></h1>'%(escape(url),escape(url))
            for match in matched:
                _matched = match.get('matched')
                _named = match.get('name')
                header = '<div class="text">%s'%(_named.replace('_',' '))
                body = ''
                # find same thing in multiple context
                if match.get('multi_context'):
                    # remove duplicate
                    no_dup = []
                    for context in match.get('context'):
                        if context not in no_dup:
                            body += '</a><div class="container">%s</div></div>'%(context)
                            body = body.replace(
                                context,'<span style="background-color:yellow">%s</span>'%context)
                            no_dup.append(context)
                        # --
                else:
                    body += '</a><div class="container">%s</div></div>'%(match.get('context')[0] if len(match.get('context'))>1 else match.get('context'))
                    body = body.replace(
                        match.get('context')[0] if len(match.get('context')) > 0 else ''.join(match.get('context')),
                        '<span style="background-color:yellow">%s</span>'%(match.get('context') if len(match.get('context'))>1 else match.get('context'))
                    )
                output += header + body
    if args.output != 'cli':
        html_save(output)
