# Spam Analysis New - ServiceNow
Phishing Story Checklist

Here's some things to double check are set up to ensure this story works smoothly!

*** Credentials ***

- URLScan.io API Key named 'urlscan_io'

- VirusTotal API Key named 'virustotal'

- HybridAnalysis API Key named 'HybridAnalysisAPI'

- emailrep.io API Key named 'emailrep'

- IPQualityScore API Key named 'ipqualityscore'

- Maxmind Licence Key named 'maxmind'

- ServiceNow API Key named 'servicenow'

- OAuth, JWT, or Text credential used to access the target mailbox. This may be through IMAP, Microsoft Graph API, GSuite API, or another provider.


*** Resources ***

- Array Resource named 'known_good_domains' used to store domains that should not be scanned

- Array Resource named 'known_good_email_domains' used to store email domains that should not be scanned

- Text Resource named 'the_hive_url' containing the domain of your ServiceNow instances (e.g. https://your-hive-instance.com/) 

- Text Resource named 'maxmind_account_id' containing the Maxmind Account ID