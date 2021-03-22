terraform {
    required_providers {
        tines = {
        source = "github.com/tuckner/tines"
        version = ">=0.0.13"
        }
    }
}

provider "tines" {
    email    = var.tines_email
    base_url = var.tines_base_url
    token    = var.tines_token
}

resource "tines_story" "spam_analysis_new_-_jira" {
    name = "Spam Analysis New - Jira"
    team_id = var.team_id
    description = <<EOF
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
EOF
}


resource "tines_global_resource" "o365_mail_account" {
    name = "o365_mail_account"
    value_type = "text"
    value = "replaceme"
}

resource "tines_global_resource" "known_good_email_domains" {
    name = "known_good_email_domains"
    value_type = "text"
    value = "replaceme"
}

resource "tines_global_resource" "jira_username" {
    name = "jira_username"
    value_type = "text"
    value = "replaceme"
}

resource "tines_global_resource" "maxmind_account_id" {
    name = "maxmind_account_id"
    value_type = "text"
    value = "replaceme"
}

resource "tines_global_resource" "jira_domain" {
    name = "jira_domain"
    value_type = "text"
    value = "replaceme"
}

resource "tines_global_resource" "imap_mail_server" {
    name = "imap_mail_server"
    value_type = "text"
    value = "replaceme"
}

resource "tines_global_resource" "known_good_domains" {
    name = "known_good_domains"
    value_type = "text"
    value = "replaceme"
}

resource "tines_agent" "read_mail_0" {
    name = "Read Mail"
    agent_type = "Agents::IMAPAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_no_eml_attachment_1.id, tines_agent.trigger_if_eml_attachment_2.id]
    position = {
      x = 930.0
      y = 255.0
    }
    agent_options = jsonencode({"conditions": {}, "emit_headers": "true", "folders": ["INBOX"], "host": "{{.RESOURCE.imap_mail_server}}", "manual_time": "60", "mark_as_read": "true", "password": "{{.CREDENTIAL.imap_password}}", "ssl": true, "username": "report-phishing@tines.xyz"})
}

resource "tines_agent" "trigger_if_no_eml_attachment_1" {
    name = "Trigger if No EML Attachment"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.create_issue_in_jira_3.id]
    position = {
      x = 735.0
      y = 330.0
    }
    agent_options = jsonencode({"rules": [{"path": "{% assign files = .read_mail.attachments | jsonpath: \u0027*.filename\u0027%}{{files}}", "type": "!regex", "value": "\\.eml"}, {"path": "{% assign file_types = .read_mail.attachments | jsonpath: \u0027*.content_type\u0027%}{{file_types}}", "type": "!regex", "value": "rfc822"}]})
}

resource "tines_agent" "trigger_if_eml_attachment_2" {
    name = "Trigger if EML Attachment"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.add_reporter_13.id]
    position = {
      x = 1050.0
      y = 330.0
    }
    agent_options = jsonencode({"must_match": "1", "rules": [{"path": "{% assign files = .read_mail.attachments | jsonpath: \u0027*.filename\u0027%}{{files}}", "type": "regex", "value": "\\.eml"}, {"path": "{% assign file_types = .read_mail.attachments | jsonpath: \u0027*.content_type\u0027%}{{file_types}}", "type": "regex", "value": "rfc822"}]})
}

resource "tines_agent" "create_issue_in_jira_3" {
    name = "Create Issue in Jira"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.check_for_urls_18.id, tines_agent.check_for_attachments_28.id, tines_agent.analyze_sender_37.id, tines_agent.check_for_emails_in_body_39.id]
    position = {
      x = 735.0
      y = 810.0
    }
    agent_options = jsonencode({"basic_auth": ["{{.RESOURCE.jira_username}}", "{{.CREDENTIAL.jira}}"], "content_type": "json", "log_error_on_status": [], "manual_time": "600", "method": "post", "payload": {"fields": {"description": "Subject {{.read_mail.subject}} \n\n*Body*\n{code:title=Email Body:|theme=DJango|linenumbers=true|language=html|firstline=0001|collapse=true|borderStyle=solid} \n{{.read_mail.body\u00a0| replace: \u0027\u003cbr\u003e\u0027, \u0027\n\u0027\u00a0|\u00a0strip_html | replace: \u0027\u0026nbsp;\u0027, \u0027\u0027 |regex_replace \u0027\\n\u0027, \u0027\u0027 | truncate: 10000, \"\n### ERROR ### This Email Body is too long to include, it has been truncated.\"\u00a0}} {code} \n\n\n\n*Headers*\n{code:json} {{.read_mail.headers | neat_json  }} {code}\n\n*Attachments:* {% if read_mail.attachments.first.filename %}\n{% for attachment in read_mail.attachments %}{{ attachment.filename }}, {{ attachment.sizeinbytes }} bytes\n{% endfor %}{% else %}No attachments identified{% endif %}\n\nTo track progress in Tines click [here|{% story_run_link %}]", "issuetype": {"name": "Task"}, "project": {"key": "DEMO"}, "summary": "Email Reported by {{.add_reporter.reporter | default: .read_mail.from}} with the subject {{.read_mail.subject}}"}}, "url": "https://{{ .RESOURCE.jira_domain }}/rest/api/2/issue"})
}

resource "tines_agent" "receive_eml_file_4" {
    name = "Receive EML File"
    agent_type = "Agents::WebhookAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.read_mail_5.id]
    position = {
      x = 1290.0
      y = 570.0
    }
    agent_options = jsonencode({"secret": "863e826237b90516bfc656a27bd29fc2", "verbs": "get,post"})
}

resource "tines_agent" "read_mail_5" {
    name = "Read Mail"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_headers_17.id]
    position = {
      x = 1290.0
      y = 660.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": "{{.receive_eml_file.body.upload_eml_file.contents | base64_decode | eml_parse | as_object}}"})
}

resource "tines_agent" "o365_get_mails_6" {
    name = "o365 Get Mails"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_mail_array_7.id, tines_agent.trigger_if_additional_mails_10.id]
    position = {
      x = -105.0
      y = -195.0
    }
    agent_options = jsonencode({"headers": {"Authorization": "Bearer {{.CREDENTIAL.o365_graph_mail_actions}}"}, "method": "get", "url": "https://graph.microsoft.com/v1.0/users/{{.RESOURCE.o365_mail_account}}/messages?$filter=isRead ne true"})
}

resource "tines_agent" "explode_mail_array_7" {
    name = "Explode Mail Array"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.get_individual_email_8.id, tines_agent.mark_email_as_read_9.id]
    position = {
      x = -105.0
      y = 45.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.o365_get_mails.body.value}}", "to": "individual_mail"})
}

resource "tines_agent" "get_individual_email_8" {
    name = "Get Individual Email"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.read_mail_12.id]
    position = {
      x = -105.0
      y = 120.0
    }
    agent_options = jsonencode({"headers": {"Authorization": "Bearer {{.CREDENTIAL.o365_graph_mail_actions}}"}, "log_error_on_status": [], "method": "get", "url": "https://graph.microsoft.com/v1.0/users/{{.RESOURCE.o365_mail_account}}/messages/{{.explode_mail_array.individual_mail.id}}/$value"})
}

resource "tines_agent" "mark_email_as_read_9" {
    name = "Mark Email as Read"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = -360.0
      y = 120.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"Authorization": "Bearer {{.CREDENTIAL.o365_graph_mail_actions}}"}, "log_error_on_status": [], "method": "patch", "payload": {"isRead": "True"}, "url": "https://graph.microsoft.com/v1.0/users/{{.RESOURCE.o365_mail_account}}/messages/{{.explode_mail_array.individual_mail.id}}"})
}

resource "tines_agent" "trigger_if_additional_mails_10" {
    name = "Trigger if Additional Mails"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.o365_get_mails_11.id]
    position = {
      x = -345.0
      y = -120.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.o365_get_mails.body.[\u0027@odata.nextLink\u0027]}}", "type": "regex", "value": "https://"}]})
}

resource "tines_agent" "o365_get_mails_11" {
    name = "o365 Get Mails"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_mail_array_7.id, tines_agent.trigger_if_additional_mails_10.id]
    position = {
      x = -345.0
      y = -30.0
    }
    agent_options = jsonencode({"headers": {"Authorization": "Bearer {{.CREDENTIAL.o365_graph_mail_actions}}"}, "method": "get", "url": "{{.o365_get_mails.body.[\u0027@odata.nextLink\u0027]}}"})
}

resource "tines_agent" "read_mail_12" {
    name = "Read Mail"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = -105.0
      y = 195.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": "{{.get_individual_email.body | eml_parse | as_object}}"})
}

resource "tines_agent" "add_reporter_13" {
    name = "Add Reporter"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_attachments_14.id]
    position = {
      x = 1050.0
      y = 420.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"reporter": "{{.read_mail.from}}"}})
}

resource "tines_agent" "explode_attachments_14" {
    name = "Explode Attachments"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_eml_15.id]
    position = {
      x = 1050.0
      y = 495.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.read_mail.attachments}}", "to": "individual_attachment"})
}

resource "tines_agent" "trigger_if_eml_15" {
    name = "Trigger if EML"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.read_mail_16.id]
    position = {
      x = 1050.0
      y = 570.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.explode_attachments.individual_attachment.filename}}", "type": "regex", "value": ".eml"}]})
}

resource "tines_agent" "read_mail_16" {
    name = "Read Mail"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_headers_17.id]
    position = {
      x = 1050.0
      y = 645.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": "{{.explode_attachments.individual_attachment.base64encodedcontents  | base64url_decode | eml_parse | as_object }}"})
}

resource "tines_agent" "analyze_headers_17" {
    name = "Analyze Headers"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.create_issue_in_jira_3.id]
    position = {
      x = 1050.0
      y = 735.0
    }
    agent_options = jsonencode({"payload": {"headers": "{{.read_mail.headers | as_object}}"}, "story": "{{ .STORY.martin_spam.sts_analyze_headers}}"})
}

resource "tines_agent" "check_for_urls_18" {
    name = "Check for URLs"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_no_urls_19.id, tines_agent.trigger_if_urls_20.id]
    position = {
      x = 1695.0
      y = 885.0
    }
    agent_options = jsonencode({"emit_no_match": "true", "rules": [{"path": "{{.read_mail.body}}", "type": "regex", "value": "[A-Za-z]+:\\/\\/[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_:%\u0026;\\?\\#\\/.=]+"}]})
}

resource "tines_agent" "trigger_if_no_urls_19" {
    name = "Trigger if No URLs"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_27.id]
    position = {
      x = 1575.0
      y = 960.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .check_for_urls.rule_matched}}", "type": "regex", "value": "false"}]})
}

resource "tines_agent" "trigger_if_urls_20" {
    name = "Trigger if URLs"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.extract_urls_21.id]
    position = {
      x = 1800.0
      y = 960.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .check_for_urls.rule_matched}}", "type": "regex", "value": "true"}]})
}

resource "tines_agent" "extract_urls_21" {
    name = "Extract URLs"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_urls_22.id]
    position = {
      x = 1800.0
      y = 1035.0
    }
    agent_options = jsonencode({"matchers": [{"path": "{{.read_mail.body}}", "regexp": "[A-Za-z]+:\\/\\/[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_:%\u0026;\\?\\#\\/.=]+", "to": "urls"}], "mode": "extract"})
}

resource "tines_agent" "explode_urls_22" {
    name = "Explode URLs"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_url_23.id]
    position = {
      x = 1800.0
      y = 1110.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.extract_urls.urls | uniq | as_object}}", "to": "individual_url"})
}

resource "tines_agent" "analyze_url_23" {
    name = "Analyze URL"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_url_in_virustotal_24.id, tines_agent.upload_attachment_to_jira_54.id]
    position = {
      x = 1800.0
      y = 1185.0
    }
    agent_options = jsonencode({"payload": {"url": "{{.explode_urls.individual_url}}"}, "story": "{{ .STORY.martin_spam.sts_analyze_url_in_urlscan}}"})
}

resource "tines_agent" "analyze_url_in_virustotal_24" {
    name = "Analyze URL in VirusTotal"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_url_array_25.id]
    position = {
      x = 1800.0
      y = 1260.0
    }
    agent_options = jsonencode({"payload": {"submit_if_not_found": "false", "url": "{{.explode_urls.individual_url}}"}, "story": "{{ .STORY.martin_spam.sts_analyze_url_in_virustotal}}"})
}

resource "tines_agent" "implode_url_array_25" {
    name = "Implode URL Array"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_26.id]
    position = {
      x = 1800.0
      y = 1350.0
    }
    agent_options = jsonencode({"guid_path": "{{.explode_urls.guid}}", "mode": "implode", "size_path": "{{.explode_urls.size}}"})
}

resource "tines_agent" "build_results_26" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_48.id]
    position = {
      x = 1800.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"all_results": "{% capture all_results %}{% for result in .implode_url_array %}\n{% if result.analyze_url.malicious == \u0027true\u0027 or result.analyze_url_in_virustotal.malicious == \u0027true\u0027%}\ntrue\n{% else %}\nfalse\n{% endif %}\n{% endfor %}{% endcapture %}{{all_results}}", "any_malicious": "{% if all_results contains \u0027true\u0027 %}true{% else %}false{% endif %}", "raw": "{{.implode_url_array | as_object}}", "total_analyzed": "{{.implode_url_array.size}}", "type": "url"}})
}

resource "tines_agent" "build_results_27" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_48.id]
    position = {
      x = 1575.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"all_results": "false", "any_malicious": "false", "total_analyzed": "0", "type": "url"}})
}

resource "tines_agent" "check_for_attachments_28" {
    name = "Check for Attachments"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_no_attachments_29.id, tines_agent.trigger_if_attachments_found_30.id]
    position = {
      x = 735.0
      y = 885.0
    }
    agent_options = jsonencode({"emit_no_match": "true", "rules": [{"path": "{{.read_mail.attachments.size }}", "type": "field\u003e=value", "value": "1"}]})
}

resource "tines_agent" "trigger_if_no_attachments_29" {
    name = "Trigger if No Attachments"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_36.id]
    position = {
      x = 540.0
      y = 960.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.check_for_attachments.rule_matched}}", "type": "field==value", "value": "false"}]})
}

resource "tines_agent" "trigger_if_attachments_found_30" {
    name = "Trigger if Attachments Found"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_attachments_31.id]
    position = {
      x = 825.0
      y = 960.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.check_for_attachments.rule_matched}}", "type": "field==value", "value": "true"}]})
}

resource "tines_agent" "explode_attachments_31" {
    name = "Explode Attachments"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_attachment_in_virustotal_32.id]
    position = {
      x = 825.0
      y = 1050.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.read_mail.attachments}}", "to": "individual_attachment"})
}

resource "tines_agent" "analyze_attachment_in_virustotal_32" {
    name = "Analyze Attachment in VirusTotal"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_attachment_33.id]
    position = {
      x = 825.0
      y = 1125.0
    }
    agent_options = jsonencode({"payload": {"contents": "{{.explode_attachments.individual_attachment.base64encodedcontents}}", "filename": "{{.explode_attachments.individual_attachment.filename}}", "hash": "{{.explode_attachments.individual_attachment.sha256}}", "submit_if_not_found": "false"}, "story": "{{ .STORY.martin_spam.sts_analyse_file_in_virustotal}}"})
}

resource "tines_agent" "analyze_attachment_33" {
    name = "Analyze Attachment"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_attachments_34.id]
    position = {
      x = 825.0
      y = 1215.0
    }
    agent_options = jsonencode({"payload": {"contents": "{{.explode_attachments.individual_attachment.base64encodedcontents}}", "filename": "{{.explode_attachments.individual_attachment.filename}}", "hash": "{{.explode_attachments.individual_attachment.sha256}}", "submit_if_not_found": "false"}, "story": "{{ .STORY.martin_spam.sts_analyze_file_in_hybridanalysis }}"})
}

resource "tines_agent" "implode_attachments_34" {
    name = "Implode Attachments"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_35.id]
    position = {
      x = 825.0
      y = 1305.0
    }
    agent_options = jsonencode({"guid_path": "{{.explode_attachments.guid }}", "mode": "implode", "size_path": "{{.explode_attachments.size }}"})
}

resource "tines_agent" "build_results_35" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_48.id]
    position = {
      x = 825.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"all_results": "{% capture all_results %}{% for result in .implode_url_array %}\n{% if result.analyze_url.malicious == \u0027true\u0027 or result.analyze_url_in_virustotal.malicious == \u0027true\u0027%}\ntrue\n{% else %}\nfalse\n{% endif %}\n{% endfor %}{% endcapture %}{{all_results}}", "any_malicious": "{% if all_results contains \u0027true\u0027 %}true{% else %}false{% endif %}", "raw": "{{.implode_attachments | as_object}}", "total_analyzed": "{{.implode_url_array.size}}", "type": "attachment"}})
}

resource "tines_agent" "build_results_36" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_48.id]
    position = {
      x = 540.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"all_results": "false", "any_malicious": "false", "total_analyzed": "0", "type": "attachment"}})
}

resource "tines_agent" "analyze_sender_37" {
    name = "Analyze Sender"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_41.id]
    position = {
      x = 1125.0
      y = 885.0
    }
    agent_options = jsonencode({"payload": {"email": "{{.read_mail.from}}"}, "story": "{{ .STORY.martin_spam.sts_analyze_email_address }}"})
}

resource "tines_agent" "trigger_if_no_emails_in_body_38" {
    name = "Trigger if No Emails in Body"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_47.id]
    position = {
      x = -300.0
      y = 975.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .check_for_emails_in_body.rule_matched }}", "type": "field==value", "value": "false"}]})
}

resource "tines_agent" "check_for_emails_in_body_39" {
    name = "Check for Emails in Body"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_no_emails_in_body_38.id, tines_agent.trigger_if_emails_exist_40.id]
    position = {
      x = -165.0
      y = 885.0
    }
    agent_options = jsonencode({"emit_no_match": "true", "rules": [{"path": "{{.read_mail.body }}", "type": "regex", "value": "(?:[a-z0-9!#$%\u0026\u0027*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%\u0026\u0027*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])"}]})
}

resource "tines_agent" "trigger_if_emails_exist_40" {
    name = "Trigger if Emails Exist"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.extract_emails_42.id]
    position = {
      x = -45.0
      y = 975.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .check_for_emails_in_body.rule_matched }}", "type": "field==value", "value": "true"}]})
}

resource "tines_agent" "build_results_41" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_48.id]
    position = {
      x = 1125.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"any_malicious": "{{.analyze_sender.malicious }}", "raw": "{{.analyze_sender | as_object}}", "total_analyzed": "1", "type": "sender"}})
}

resource "tines_agent" "extract_emails_42" {
    name = "Extract Emails"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_email_array_43.id]
    position = {
      x = -45.0
      y = 1065.0
    }
    agent_options = jsonencode({"matchers": [{"path": "{{.read_mail.body }}", "regexp": "(?:[a-z0-9!#$%\u0026\u0027*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%\u0026\u0027*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])", "to": "emails"}], "mode": "extract"})
}

resource "tines_agent" "explode_email_array_43" {
    name = "Explode Email Array"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_email_44.id]
    position = {
      x = -45.0
      y = 1140.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.extract_emails.emails | uniq | as_object }}", "to": "individual_email"})
}

resource "tines_agent" "analyze_email_44" {
    name = "Analyze Email"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_emails_45.id]
    position = {
      x = -45.0
      y = 1215.0
    }
    agent_options = jsonencode({"payload": {"email": "{{.explode_email_array.individual_email}}"}, "story": "{{ .STORY.martin_spam.sts_analyze_email_address }}"})
}

resource "tines_agent" "implode_emails_45" {
    name = "Implode Emails"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_46.id]
    position = {
      x = -45.0
      y = 1290.0
    }
    agent_options = jsonencode({"guid_path": "{{.explode_email_array.guid }}", "mode": "implode", "size_path": "{{.explode_email_array.size }}"})
}

resource "tines_agent" "build_results_46" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_48.id]
    position = {
      x = -45.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"all_results": "{% capture all_results %}{% for result in .implode_emails %}\n{% if result.analyze_email.malicious == \u0027true\u0027 %}\ntrue\n{% else %}\nfalse\n{% endif %}\n{% endfor %}{% endcapture %}{{all_results}}", "any_malicious": "{% if all_results contains \u0027true\u0027 %}true{% else %}false{% endif %}", "raw": "{{.implode_emails | as_object}}", "total_analyzed": "{{.implode_emails.size}}", "type": "email"}})
}

resource "tines_agent" "build_results_47" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_48.id]
    position = {
      x = -300.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"all_results": "", "any_malicious": "false", "total_analyzed": "0", "type": "email"}})
}

resource "tines_agent" "implode_analysis_48" {
    name = "Implode Analysis"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_jira_content_49.id]
    position = {
      x = 750.0
      y = 1515.0
    }
    agent_options = jsonencode({"guid_path": "{{.read_mail.message_id }}", "mode": "implode", "size_path": "4"})
}

resource "tines_agent" "build_jira_content_49" {
    name = "Build Jira Content"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.prompt_response_51.id, tines_agent.update_case_52.id]
    position = {
      x = 750.0
      y = 1590.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"attachments": "{% assign attachment_results = .implode_analysis | where: \"build_results.type\", \u0027attachment\u0027 | map: \u0027build_results\u0027%}\n\n*Attachment Results:* \n{% if attachment_results.first.total_analyzed == 0 %}No Results Found{% else %}\n||*File Name*||*Hash*||*HybridAnalysis Verdict*||*VirusTotal Verdict*||*New*||*Response Actions*||{% for attachment in attachment_results.first.raw %}\n|{{attachment.explode_attachments.individual_attachment.filename}}|{{.attachment.explode_attachments.individual_attachment.sha256}}|[{% if attachment.analyze_attachment.malicious == \u0027true\u0027%}\u274c Malicious{% else %}\u2705 Not Malicious{% endif %}|{{attachment.analyze_attachment.analysis_link | default: \u0027https://hybridanalysis.com\u0027}}] |[{% if attachment.analyze_attachment_in_virustotal.malicious == \u0027true\u0027%}\u274c Malicious{% else %}\u2705 Not Malicious{% endif %}|{{attachment.analyze_attachment_in_virustotal.analysis_link | default: \u0027https://virustotal.com\u0027}}] |{{attachment.analyze_attachment.new }}  |[Ban Hash|https://tines.io] |{% endfor %}\n{% endif %}", "body_emails": "{% assign email_results = .implode_analysis | where: \"build_results.type\", \u0027email\u0027 | map: \u0027build_results\u0027%}\n\n*Email Analysis Results:* \n{% if email_results.build_results.total_analyzed == 0 %}No email addresses found in the mail body.{% else %}\n||*Email Address*||*Malicious*||*CEO Fraud*||*Blacklisted*||*Suspicious*||*Disposable Email*||*Domain Age*||{% for address in email_results.first.raw %}\n|{{address.explode_email_array.individual_email}} |{% if .address.analyze_email.malicious == \u0027true\u0027 %}\u274c Malicious{% else %}\u2705 Not Malicious{% endif %} |{{address.analyze_email.ceo_fraud}} |{{address.analyze_email.email_blacklisted}} |{{address.analyze_email.suspicious_email}} |{{address.analyze_email.disposable_email}} |{{address.analyze_email.email_domain_age}} |{% endfor %}\n{% endif %}", "headers": "{% if analyze_headers %}*Header Analysis Results*:\n||*DMARC*||*SPF*||*DKIM*||*IP*||*ASN*||*IP Location*||*Recent Spam*||*IP Reputation*||\n |{{.analyze_headers.dmarc}}|{{.analyze_headers.spf}}|{{.analyze_headers.dkim}}|{{.analyze_headers.initial_ip}}|{{.analyze_headers.organization}}|{{.analyze_headers.city}},{{.analyze_headers.country}}|{{.analyze_headers.recent_spam_activity}}|{{.analyze_headers.ip_sender_reputation}}|{% endif %}", "sender_email": "{% assign sender_results = .implode_analysis | where: \"build_results.type\", \u0027sender\u0027 | map: \u0027build_results\u0027%}\n\n*Sender Analysis Results:*\n||*Email Address*||*Malicious*||*CEO Fraud*||*Blacklisted*||*Suspicious*||*Disposable Email*||*Domain Age*||\n|{{.sender_results.first.raw.email_address}} |{% if .sender_results.first.raw.malicious == true %}\u274c Malicious{% else %}\u2705 Not Malicious{% endif %} |{{.sender_results.first.raw.ceo_fraud}} |{{.sender_results.first.raw.email_blacklisted}} |{{.sender_results.first.raw.suspicious_email}} |{{.sender_results.first.raw.disposable_email}} |{{.sender_results.first.raw.email_domain_age}} |", "summary": "[Tines Event Link|{% story_run_link %}]\n[Click here to contain this device in Crowdstrike|{% prompt contain %}]\n ---- {% assign all_results = .implode_analysis | jsonpath: \u0027*.build_results.any_malicious\u0027 %}\n*Overall Classification:* {% if all_results contains \"true\" %}{color:red} *\u274c MALICIOUS* {color}{% else %}{color:green} *\u2705 Not Malicious* {color}{% endif %}\n\n----\n\nh2.{color:teal} (*b) +Analysis results for this email can be found below+ (*b) {color}\n", "urls": "{% assign url_results = .implode_analysis | where: \"build_results.type\", \u0027url\u0027 | map: \u0027build_results\u0027%}\n\n*URL Analysis Results:* \n{% if url_results.first.total_analyzed == 0 %}No URLs found in this mail{% else %}\n||*URL*||*URLScan Verdict*||*Analysis Date*||*VirusTotal Verdict*||*Response Actions*||{% for url in url_results.first.raw %}\n|{{url.explode_urls.individual_url | regex_replace: \u0027https?://\u0027, \u0027hxxps?//\u0027 | replace: \u0027.\u0027, \u0027[.]\u0027}} |[{% if url.analyze_url.malicious == \u0027true\u0027%}\u274c Malicious{% else %}\u2705 Not Malicious{% endif %}|{{url.analyze_url.analysis_link | default: \u0027https://urlscan.io\u0027}}] |{{url.analyze_url.analysis_date}} |[{% if url.analyze_url_in_virustotal.malicious == \u0027true\u0027%}\u274c Malicious{% else %}\u2705 Not Malicious{% endif %}|{{url.analyze_url_in_virustotal.analysis_link | default: \u0027https://virustotal.com\u0027}}] |[Block Domains|https://tines.io] |{% endfor %}\n\n{% endif %}"}})
}

resource "tines_agent" "update_jira_with_analysis_50" {
    name = "Update jira with analysis"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 750.0
      y = 1815.0
    }
    agent_options = jsonencode({"basic_auth": ["{{ .RESOURCE.jira_username }}", "{{ .CREDENTIAL.jira }}"], "content_type": "json", "log_error_on_status": [], "manual_time": "600", "method": "put", "payload": {"fields": {"description": "{{.build_jira_content.summary}}\n\n{{.get_jira_issue.body.fields.description}}\n\n{{.build_jira_content.headers}}\n\n{{.build_jira_content.urls }}\n\n{{.build_jira_content.attachments }}\n\n{{.build_jira_content.sender_email}}\n\n{{.build_jira_content.body_emails }}"}}, "url": "https://{{ .RESOURCE.jira_domain }}/rest/api/2/issue/{{.create_issue_in_jira.body.id}}/"})
}

resource "tines_agent" "prompt_response_51" {
    name = "Prompt Response"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 975.0
      y = 1665.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.build_jira_content.prompt }}", "type": "regex", "value": "."}]})
}

resource "tines_agent" "update_case_52" {
    name = "Update Case"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.get_jira_issue_53.id]
    position = {
      x = 750.0
      y = 1665.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.build_jira_content.prompt }}", "type": "regex", "value": "^$"}]})
}

resource "tines_agent" "get_jira_issue_53" {
    name = "Get Jira Issue"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.update_jira_with_analysis_50.id]
    position = {
      x = 750.0
      y = 1740.0
    }
    agent_options = jsonencode({"basic_auth": ["{{ .RESOURCE.jira_username }}", "{{ .CREDENTIAL.jira }}"], "content_type": "json", "method": "get", "url": "https://{{ .RESOURCE.jira_domain }}/rest/api/2/issue/{{.create_issue_in_jira.body.id }}/"})
}

resource "tines_agent" "upload_attachment_to_jira_54" {
    name = "Upload Attachment to Jira"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 2025.0
      y = 1260.0
    }
    agent_options = jsonencode({"basic_auth": ["{{ .RESOURCE.jira_username }}", "{{ .CREDENTIAL.jira }}"], "content_type": "data", "headers": {"X-Atlassian-Token": "no-check"}, "method": "post", "payload": {"file": {"contents": "{{.analyze_url.screenshot.contents | base64_decode}}", "filename": "{{.analyze_url.url | replace: \u0027/\u0027, \u0027_\u0027 }}"}}, "url": "https://{{ .RESOURCE.jira_domain }}/rest/api/2/issue/{{.create_issue_in_jira.body.id }}/attachments"})
}

resource "tines_agent" "get_emails_55" {
    name = "Get emails"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_emails_56.id]
    position = {
      x = 1575.0
      y = -165.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"Authorization": "Bearer {{.CREDENTIAL.gmail_read_oauth }}"}, "method": "get", "payload": {"q": "in:inbox after:{{ \"now\" | date: \"%s\" | minus: 480 }}"}, "url": "https://www.googleapis.com/gmail/v1/users/phishing@tines.com/messages"})
}

resource "tines_agent" "explode_emails_56" {
    name = "Explode emails"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.dedupe_emails_57.id]
    position = {
      x = 1575.0
      y = -90.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.get_emails.body.messages}}", "to": "email"})
}

resource "tines_agent" "dedupe_emails_57" {
    name = "Dedupe Emails"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.get_email_by_id_58.id]
    position = {
      x = 1575.0
      y = -30.0
    }
    agent_options = jsonencode({"lookback": "100", "mode": "deduplicate", "path": "{{.explode_emails.email.id}}{{.get_emails.message_id}}"})
}

resource "tines_agent" "get_email_by_id_58" {
    name = "Get email by id"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.read_mail_59.id]
    position = {
      x = 1575.0
      y = 45.0
    }
    agent_options = jsonencode({"headers": {"Authorization": "Bearer {{.CREDENTIAL.gmail_read_oauth }}"}, "method": "get", "payload": {"format": "raw"}, "url": "https://www.googleapis.com/gmail/v1/users/phishing@tines.com/messages/{{.explode_emails.email.id}}"})
}

resource "tines_agent" "read_mail_59" {
    name = "Read Mail"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_jira.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 1575.0
      y = 120.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": "{{.get_email_by_id.body.raw | base64url_decode | eml_parse | as_object }}"})
}

resource "tines_note" "note_0" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
IMAP Action

The IMAP action will connect to a mailbox where the mailserver is configured to have IMAP enabled.

Enter the mailserver, the username and the password to connect any begin reading mails.

The first time this Action is run, the mailbox state will be recorded and any future mails will be read into Tines on subsequent Action queries.
EOF
    position = {
      x = 645.0
      y = 60.0
    }
}

resource "tines_note" "note_1" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
EML Handling

Some users or report phish buttons will forward the suspicious email as a .eml attachment.

In these cases, we want to identify these attachments and analyze this eml file including email headers.
EOF
    position = {
      x = 1275.0
      y = 345.0
    }
}

resource "tines_note" "note_2" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Submitting by Form

This story is also able to receive eml files through the Tines Form. 
Any submitted EMLs will be received by this Webhook Action and will be processed as normal.
EOF
    position = {
      x = 1515.0
      y = 585.0
    }
}

resource "tines_note" "note_3" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Creating Incident Ticket

Before any email content is analyzed we can create an issue in the security case management system.
This will contain basic mail info such as subject, body, and headers.
EOF
    position = {
      x = 420.0
      y = 720.0
    }
}

resource "tines_note" "note_4" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Analyzing Sender

To check the reputation of the sender of the suspicious email it is submitted to a Tines Sub-Story which will analyze the email address and return the results to this story.
EOF
    position = {
      x = 1170.0
      y = 990.0
    }
}

resource "tines_note" "note_5" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Analyzing URLs

Any URLs found in the body of the email are identified and extracted.

We're then exploding the array of extracted URLs so that we can look at these URLs individually.

Each URL will be analyzed by URLScan and VirusTotal. 
URL screenshots will be uploaded to Jira to provide extra context.

EOF
    position = {
      x = 2025.0
      y = 975.0
    }
}

resource "tines_note" "note_6" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Imploding and Building Results

The Implode Action will wait until all URLs have been analyzed and results returned. It will then merge these results into one event which will be available later.

Build Results will summarise the results of URL analysis and indicate whether any of the URLs were malicious, and how many URLs were analyzed in total.
EOF
    position = {
      x = 2025.0
      y = 1335.0
    }
}

resource "tines_note" "note_7" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Analyzing Attachments

Any attachments found in the reported email will be analyzed in this flow.

Each attachment will be analyzed individually in VirusTotal and HybridAnalysis. When set to 'true', the 'submit_if_not_found' field will upload the file to the scan engine if it has not been seen before. If set to 'false' or removed completely, it will not be submitted and the story will only pull back existing results.
EOF
    position = {
      x = 240.0
      y = 960.0
    }
}

resource "tines_note" "note_8" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Imploding and Building Results

The Implode Action will wait until all attachments have been analyzed and results returned. It will then merge these results into one event which will be available later.

Build Results will summarise the results of attachment analysis and indicate whether any of the URLs were malicious, and how many attachments were analyzed in total.
EOF
    position = {
      x = 240.0
      y = 1275.0
    }
}

resource "tines_note" "note_9" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Analyzing Emails

In cases where the internal users reports the email by forwarding it inline, rather than as an attachment, we will want to check the body for any email addresses found, and check the reputation of these individually.
EOF
    position = {
      x = -615.0
      y = 975.0
    }
}

resource "tines_note" "note_10" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Imploding and Building Results

The Implode Action will wait until all email addresses have been analyzed and results returned. It will then merge these results into one event which will be available later.

Build Results will summarise the results of email address analysis and indicate whether any of the URLs were malicious, and how many email addresses were analyzed in total.
EOF
    position = {
      x = -615.0
      y = 1290.0
    }
}

resource "tines_note" "note_11" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Tying Everything Together

This Implode Action will wait for all previous analysis to complete, and bring everything together in one event so we can prepare the results.
EOF
    position = {
      x = 945.0
      y = 1515.0
    }
}

resource "tines_note" "note_12" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Presenting the Results

In the Build Jira Content Action we are going to build the Jira formatted content that the analyst will actually review.
The 'assign' block in this action is looking in the event output from Implode Analysis for the relevant analysis 'type'; URL, Attachment, Email, or Sender.
Any additions, or updates needed in the Jira Incident can be modified in the Build Jira Content Action.

EOF
    position = {
      x = 465.0
      y = 1590.0
    }
}

resource "tines_note" "note_13" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Handling Prompts

We are adding a couple of Trigger Actions here to handle Prompt Responses. If there is a Prompt included in the Jira ticket - for example to Contain the Device in Crowdstrike - then these Actions will route the response to the right place.
EOF
    position = {
      x = 1185.0
      y = 1665.0
    }
}

resource "tines_note" "note_14" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Updating Jira

First we're getting the Jira ticket content. We don't want to overwrite any information added to the case by an analyst while this Story was running, so we are updating the Jira case to include:

- An overall verdict on the mail
- The initial case description including mail body and headers
- Attachment, URL, Sender and Email analysis

EOF
    position = {
      x = 885.0
      y = 1905.0
    }
}

resource "tines_note" "note_15" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Reading Mails with o365

The first Action here will connect to the Microsoft Graph API and retrieve a list of all unread mails.

We're including a pagination loop here will repeat the 'Get Mail' query if there are more available.
EOF
    position = {
      x = -405.0
      y = -315.0
    }
}

resource "tines_note" "note_16" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Parsing the Mail

The mails come through as an Array, and using the Explode Action allows us to look at these individually

Next, we're marking the mail as read so we only process it once.
'Get Individual Email' is using the Email ID from previous events to retrieve the Raw email which will include extra information like the mail headers.
Lastly, this raw email content is being parse into a regular email structure.

 
EOF
    position = {
      x = 120.0
      y = 0.0
    }
}

resource "tines_note" "note_17" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Reading Mails with GSuite

The first Action here will connect to the GMail API and retrieve a list of all mails received in the past 8 minutes or so. This Action should be scheduled to run every 5 minutes or so. The overlap between the schedule time, and the lookback time will ensure a mail does not get missed.

This Action uses an OAuth Token belonging to the Mailbox we're reading. This can also be a Service Account JWT Token, if necessary.
EOF
    position = {
      x = 1290.0
      y = -270.0
    }
}

resource "tines_note" "note_18" {
    story_id = tines_story.spam_analysis_new_-_jira.id
    content = <<EOF
Parsing the Mail

The array of email IDs is being exploded into individual events so we can handle each mail by itself.

The Dedup Action will ensure that each mail is only examined once.

Next, using the original mail ID we can get the raw Base64Encoded Email Body, which we will then parse into the regular email format.

EOF
    position = {
      x = 1785.0
      y = -15.0
    }
}
