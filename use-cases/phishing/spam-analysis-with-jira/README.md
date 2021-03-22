# Spam Analysis New - Jira
Phishing Story Checklist

Here's some things to double check are set up to ensure this story works smoothly!

*** Credentials ***

- URLScan.io API Key named 'urlscan_io'

- VirusTotal API Key named 'virustotal'

- HybridAnalysis API Key named 'HybridAnalysisAPI'

- emailrep.io API Key named 'emailrep'

- IPQualityScore API Key named 'ipqualityscore'

- Maxmind Licence Key named 'maxmind'

- Jira service account password named 'jira'

- OAuth, JWT, or Text credential used to access the specified mailbox.


*** Resources ***

- Array Resource named 'known_good_domains' used to store domains that should not be scanned

- Array Resource named 'known_good_email_domains' used to store email domains that should not be scanned

- Text Resource named 'jira_domain' containing the domain of your Jira instance (e.g. tines.atlassian.net) 

- Text Resource named 'jira_username' containing the username of the service account used to access Jira

- Text Resource named 'maxmind_account_id' containing the Maxmind Account ID