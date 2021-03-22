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

resource "tines_story" "spam_analysis_new_-_servicenow" {
    name = "Spam Analysis New - ServiceNow"
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

- ServiceNow API Key named 'servicenow'

- OAuth, JWT, or Text credential used to access the target mailbox. This may be through IMAP, Microsoft Graph API, GSuite API, or another provider.


*** Resources ***

- Array Resource named 'known_good_domains' used to store domains that should not be scanned

- Array Resource named 'known_good_email_domains' used to store email domains that should not be scanned

- Text Resource named 'the_hive_url' containing the domain of your ServiceNow instances (e.g. https://your-hive-instance.com/) 

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

resource "tines_global_resource" "servicenowdomain" {
    name = "servicenowdomain"
    value_type = "text"
    value = "replaceme"
}

resource "tines_global_resource" "maxmind_account_id" {
    name = "maxmind_account_id"
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

resource "tines_global_resource" "servicenowurl" {
    name = "servicenowurl"
    value_type = "text"
    value = "replaceme"
}

resource "tines_agent" "trigger_if_no_eml_attachment_0" {
    name = "Trigger if No EML Attachment"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.create_new_incident_ticket_in_servicenow_56.id]
    position = {
      x = 735.0
      y = 330.0
    }
    agent_options = jsonencode({"rules": [{"path": "{% assign files = .read_mail.attachments | jsonpath: \u0027*.filename\u0027%}{{files}}", "type": "!regex", "value": "\\.eml"}, {"path": "{% assign file_types = .read_mail.attachments | jsonpath: \u0027*.content_type\u0027%}{{file_types}}", "type": "!regex", "value": "rfc822"}]})
}

resource "tines_agent" "analyze_attachment_in_virustotal_1" {
    name = "Analyze Attachment in VirusTotal"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_attachment_4.id]
    position = {
      x = 825.0
      y = 1125.0
    }
    agent_options = jsonencode({"payload": {"contents": "{{.explode_attachments.individual_attachment.base64encodedcontents}}", "filename": "{{.explode_attachments.individual_attachment.filename}}", "hash": "{{.explode_attachments.individual_attachment.sha256}}", "submit_if_not_found": "false"}, "story": "{{ .STORY.martin_spam.sts_analyse_file_in_virustotal}}"})
}

resource "tines_agent" "trigger_if_emails_exist_2" {
    name = "Trigger if Emails Exist"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.extract_emails_28.id]
    position = {
      x = -45.0
      y = 975.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .check_for_emails_in_body.rule_matched }}", "type": "field==value", "value": "true"}]})
}

resource "tines_agent" "analyze_url_3" {
    name = "Analyze URL"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_url_in_virustotal_5.id]
    position = {
      x = 1800.0
      y = 1185.0
    }
    agent_options = jsonencode({"payload": {"url": "{{.explode_urls.individual_url}}"}, "story": "{{ .STORY.martin_spam.sts_analyze_url_in_urlscan}}"})
}

resource "tines_agent" "analyze_attachment_4" {
    name = "Analyze Attachment"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_attachments_13.id]
    position = {
      x = 825.0
      y = 1215.0
    }
    agent_options = jsonencode({"payload": {"contents": "{{.explode_attachments.individual_attachment.base64encodedcontents}}", "filename": "{{.explode_attachments.individual_attachment.filename}}", "hash": "{{.explode_attachments.individual_attachment.sha256}}", "submit_if_not_found": "false"}, "story": "{{ .STORY.martin_spam.sts_analyze_file_in_hybridanalysis }}"})
}

resource "tines_agent" "analyze_url_in_virustotal_5" {
    name = "Analyze URL in VirusTotal"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_url_array_7.id, tines_agent.upload_attachment_to_service_now_case_58.id]
    position = {
      x = 1800.0
      y = 1260.0
    }
    agent_options = jsonencode({"payload": {"submit_if_not_found": "false", "url": "{{.explode_urls.individual_url}}"}, "story": "{{ .STORY.martin_spam.sts_analyze_url_in_virustotal}}"})
}

resource "tines_agent" "extract_urls_6" {
    name = "Extract URLs"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_urls_16.id]
    position = {
      x = 1800.0
      y = 1035.0
    }
    agent_options = jsonencode({"matchers": [{"path": "{{.read_mail.body}}", "regexp": "[A-Za-z]+:\\/\\/[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_:%\u0026;\\?\\#\\/.=]+", "to": "urls"}], "mode": "extract"})
}

resource "tines_agent" "implode_url_array_7" {
    name = "Implode URL Array"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_54.id]
    position = {
      x = 1800.0
      y = 1350.0
    }
    agent_options = jsonencode({"guid_path": "{{.explode_urls.guid}}", "mode": "implode", "size_path": "{{.explode_urls.size}}"})
}

resource "tines_agent" "check_for_attachments_8" {
    name = "Check for Attachments"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_attachments_found_17.id, tines_agent.trigger_if_no_attachments_19.id]
    position = {
      x = 735.0
      y = 885.0
    }
    agent_options = jsonencode({"emit_no_match": "true", "rules": [{"path": "{{.read_mail.attachments.size }}", "type": "field\u003e=value", "value": "1"}]})
}

resource "tines_agent" "build_results_9" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_33.id]
    position = {
      x = 555.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"all_results": "false", "any_malicious": "false", "total_analyzed": "0", "type": "attachment"}})
}

resource "tines_agent" "explode_attachments_10" {
    name = "Explode Attachments"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_attachment_in_virustotal_1.id]
    position = {
      x = 825.0
      y = 1050.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.read_mail.attachments}}", "to": "individual_attachment"})
}

resource "tines_agent" "trigger_if_eml_11" {
    name = "Trigger if EML"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.read_mail_12.id]
    position = {
      x = 1050.0
      y = 570.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.explode_attachments.individual_attachment.filename}}", "type": "regex", "value": ".eml"}]})
}

resource "tines_agent" "read_mail_12" {
    name = "Read Mail"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_headers_22.id]
    position = {
      x = 1050.0
      y = 645.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": "{{.explode_attachments.individual_attachment.base64encodedcontents  | base64url_decode | eml_parse | as_object }}"})
}

resource "tines_agent" "implode_attachments_13" {
    name = "Implode Attachments"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_53.id]
    position = {
      x = 825.0
      y = 1305.0
    }
    agent_options = jsonencode({"guid_path": "{{.explode_attachments.guid }}", "mode": "implode", "size_path": "{{.explode_attachments.size }}"})
}

resource "tines_agent" "explode_attachments_14" {
    name = "Explode Attachments"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_eml_11.id]
    position = {
      x = 1050.0
      y = 495.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.read_mail.attachments}}", "to": "individual_attachment"})
}

resource "tines_agent" "build_results_15" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_33.id]
    position = {
      x = 1575.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"all_results": "false", "any_malicious": "false", "total_analyzed": "0", "type": "url"}})
}

resource "tines_agent" "explode_urls_16" {
    name = "Explode URLs"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_url_3.id]
    position = {
      x = 1800.0
      y = 1110.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.extract_urls.urls | uniq | as_object}}", "to": "individual_url"})
}

resource "tines_agent" "trigger_if_attachments_found_17" {
    name = "Trigger if Attachments Found"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_attachments_10.id]
    position = {
      x = 825.0
      y = 960.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.check_for_attachments.rule_matched}}", "type": "field==value", "value": "true"}]})
}

resource "tines_agent" "prompt_response_18" {
    name = "Prompt Response"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 1020.0
      y = 1680.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.build_service_now_content.prompt }}", "type": "regex", "value": "."}]})
}

resource "tines_agent" "trigger_if_no_attachments_19" {
    name = "Trigger if No Attachments"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_9.id]
    position = {
      x = 555.0
      y = 960.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.check_for_attachments.rule_matched}}", "type": "field==value", "value": "false"}]})
}

resource "tines_agent" "update_case_20" {
    name = "Update Case"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.update_servicenow_incident_57.id]
    position = {
      x = 750.0
      y = 1680.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.build_service_now_content.prompt }}", "type": "regex", "value": "^$"}]})
}

resource "tines_agent" "get_individual_email_21" {
    name = "Get Individual Email"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.read_mail_41.id]
    position = {
      x = -105.0
      y = 120.0
    }
    agent_options = jsonencode({"headers": {"Authorization": "Bearer {{.CREDENTIAL.o365_graph_mail_actions}}"}, "log_error_on_status": [], "method": "get", "url": "https://graph.microsoft.com/v1.0/users/{{.RESOURCE.o365_mail_account}}/messages/{{.explode_mail_array.individual_mail.id}}/$value"})
}

resource "tines_agent" "analyze_headers_22" {
    name = "Analyze Headers"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.create_new_incident_ticket_in_servicenow_56.id]
    position = {
      x = 1050.0
      y = 720.0
    }
    agent_options = jsonencode({"payload": {"headers": "{{.read_mail.headers | as_object}}"}, "story": "{{ .STORY.martin_spam.sts_analyze_headers}}"})
}

resource "tines_agent" "trigger_if_urls_23" {
    name = "Trigger if URLs"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.extract_urls_6.id]
    position = {
      x = 1800.0
      y = 960.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .check_for_urls.rule_matched}}", "type": "regex", "value": "true"}]})
}

resource "tines_agent" "analyze_sender_24" {
    name = "Analyze Sender"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_27.id]
    position = {
      x = 1275.0
      y = 885.0
    }
    agent_options = jsonencode({"payload": {"email": "{{.read_mail.from}}"}, "story": "{{ .STORY.martin_spam.sts_analyze_email_address }}"})
}

resource "tines_agent" "trigger_if_no_emails_in_body_25" {
    name = "Trigger if No Emails in Body"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_32.id]
    position = {
      x = -300.0
      y = 975.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .check_for_emails_in_body.rule_matched }}", "type": "field==value", "value": "false"}]})
}

resource "tines_agent" "check_for_emails_in_body_26" {
    name = "Check for Emails in Body"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_emails_exist_2.id, tines_agent.trigger_if_no_emails_in_body_25.id]
    position = {
      x = -165.0
      y = 885.0
    }
    agent_options = jsonencode({"emit_no_match": "true", "rules": [{"path": "{{.read_mail.body }}", "type": "regex", "value": "(?:[a-z0-9!#$%\u0026\u0027*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%\u0026\u0027*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])"}]})
}

resource "tines_agent" "build_results_27" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_33.id]
    position = {
      x = 1275.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"any_malicious": "{{.analyze_sender.malicious }}", "raw": "{{.analyze_sender | as_object}}", "total_analyzed": "1", "type": "sender"}})
}

resource "tines_agent" "extract_emails_28" {
    name = "Extract Emails"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_email_array_29.id]
    position = {
      x = -45.0
      y = 1065.0
    }
    agent_options = jsonencode({"matchers": [{"path": "{{.read_mail.body }}", "regexp": "(?:[a-z0-9!#$%\u0026\u0027*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%\u0026\u0027*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])", "to": "emails"}], "mode": "extract"})
}

resource "tines_agent" "explode_email_array_29" {
    name = "Explode Email Array"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_email_30.id]
    position = {
      x = -45.0
      y = 1140.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.extract_emails.emails | uniq | as_object }}", "to": "individual_email"})
}

resource "tines_agent" "analyze_email_30" {
    name = "Analyze Email"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_emails_31.id]
    position = {
      x = -45.0
      y = 1215.0
    }
    agent_options = jsonencode({"payload": {"email": "{{.explode_email_array.individual_email}}"}, "story": "{{ .STORY.martin_spam.sts_analyze_email_address }}"})
}

resource "tines_agent" "implode_emails_31" {
    name = "Implode Emails"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_51.id]
    position = {
      x = -45.0
      y = 1290.0
    }
    agent_options = jsonencode({"guid_path": "{{.explode_email_array.guid }}", "mode": "implode", "size_path": "{{.explode_email_array.size }}"})
}

resource "tines_agent" "build_results_32" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_33.id]
    position = {
      x = -300.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"all_results": "", "any_malicious": "false", "total_analyzed": "0", "type": "email"}})
}

resource "tines_agent" "implode_analysis_33" {
    name = "Implode Analysis"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_service_now_content_55.id]
    position = {
      x = 750.0
      y = 1515.0
    }
    agent_options = jsonencode({"guid_path": "{{.read_mail.message_id }}", "mode": "implode", "size_path": "4"})
}

resource "tines_agent" "receive_eml_file_34" {
    name = "Receive EML File"
    agent_type = "Agents::WebhookAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.read_mail_52.id]
    position = {
      x = 1290.0
      y = 570.0
    }
    agent_options = jsonencode({"secret": "863e826237b90516bfc656a27bd29fc2", "verbs": "get,post"})
}

resource "tines_agent" "read_mail_35" {
    name = "Read Mail"
    agent_type = "Agents::IMAPAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_no_eml_attachment_0.id, tines_agent.trigger_if_eml_attachment_36.id]
    position = {
      x = 960.0
      y = 255.0
    }
    agent_options = jsonencode({"conditions": {}, "emit_headers": "true", "folders": ["INBOX"], "host": "{{.RESOURCE.imap_mail_server}}", "manual_time": "60", "mark_as_read": "true", "password": "{{.CREDENTIAL.imap_password}}", "ssl": true, "username": "report-phishing@tines.xyz"})
}

resource "tines_agent" "trigger_if_eml_attachment_36" {
    name = "Trigger if EML Attachment"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.add_reporter_43.id]
    position = {
      x = 1050.0
      y = 330.0
    }
    agent_options = jsonencode({"must_match": "1", "rules": [{"path": "{% assign files = .read_mail.attachments | jsonpath: \u0027*.filename\u0027%}{{files}}", "type": "regex", "value": "\\.eml"}, {"path": "{% assign file_types = .read_mail.attachments | jsonpath: \u0027*.content_type\u0027%}{{file_types}}", "type": "regex", "value": "rfc822"}]})
}

resource "tines_agent" "o365_get_mails_37" {
    name = "o365 Get Mails"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_mail_array_38.id, tines_agent.trigger_if_additional_mails_40.id]
    position = {
      x = -105.0
      y = -195.0
    }
    agent_options = jsonencode({"headers": {"Authorization": "Bearer {{.CREDENTIAL.o365_graph_mail_actions}}"}, "method": "get", "url": "https://graph.microsoft.com/v1.0/users/{{.RESOURCE.o365_mail_account}}/messages?$filter=isRead ne true"})
}

resource "tines_agent" "explode_mail_array_38" {
    name = "Explode Mail Array"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.get_individual_email_21.id, tines_agent.mark_email_as_read_39.id]
    position = {
      x = -105.0
      y = 45.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.o365_get_mails.body.value}}", "to": "individual_mail"})
}

resource "tines_agent" "mark_email_as_read_39" {
    name = "Mark Email as Read"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = -360.0
      y = 120.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"Authorization": "Bearer {{.CREDENTIAL.o365_graph_mail_actions}}"}, "log_error_on_status": [], "method": "patch", "payload": {"isRead": "True"}, "url": "https://graph.microsoft.com/v1.0/users/{{.RESOURCE.o365_mail_account}}/messages/{{.explode_mail_array.individual_mail.id}}"})
}

resource "tines_agent" "trigger_if_additional_mails_40" {
    name = "Trigger if Additional Mails"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.o365_get_mails_42.id]
    position = {
      x = -345.0
      y = -120.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.o365_get_mails.body.[\u0027@odata.nextLink\u0027]}}", "type": "regex", "value": "https://"}]})
}

resource "tines_agent" "read_mail_41" {
    name = "Read Mail"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = -105.0
      y = 195.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": "{{.get_individual_email.body | eml_parse | as_object}}"})
}

resource "tines_agent" "o365_get_mails_42" {
    name = "o365 Get Mails"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_mail_array_38.id, tines_agent.trigger_if_additional_mails_40.id]
    position = {
      x = -345.0
      y = -30.0
    }
    agent_options = jsonencode({"headers": {"Authorization": "Bearer {{.CREDENTIAL.o365_graph_mail_actions}}"}, "method": "get", "url": "{{.o365_get_mails.body.[\u0027@odata.nextLink\u0027]}}"})
}

resource "tines_agent" "add_reporter_43" {
    name = "Add Reporter"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_attachments_14.id]
    position = {
      x = 1050.0
      y = 420.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"reporter": "{{.read_mail.from}}"}})
}

resource "tines_agent" "check_for_urls_44" {
    name = "Check for URLs"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_urls_23.id, tines_agent.trigger_if_no_urls_45.id]
    position = {
      x = 1695.0
      y = 885.0
    }
    agent_options = jsonencode({"emit_no_match": "true", "rules": [{"path": "{{.read_mail.body}}", "type": "regex", "value": "[A-Za-z]+:\\/\\/[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_:%\u0026;\\?\\#\\/.=]+"}]})
}

resource "tines_agent" "trigger_if_no_urls_45" {
    name = "Trigger if No URLs"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_15.id]
    position = {
      x = 1575.0
      y = 960.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .check_for_urls.rule_matched}}", "type": "regex", "value": "false"}]})
}

resource "tines_agent" "explode_emails_46" {
    name = "Explode emails"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.dedupe_emails_47.id]
    position = {
      x = 1680.0
      y = -45.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.get_emails.body.messages}}", "to": "email"})
}

resource "tines_agent" "dedupe_emails_47" {
    name = "Dedupe Emails"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.get_email_by_id_49.id]
    position = {
      x = 1680.0
      y = 15.0
    }
    agent_options = jsonencode({"lookback": "100", "mode": "deduplicate", "path": "{{.explode_emails.email.id}}{{.get_emails.message_id}}"})
}

resource "tines_agent" "get_emails_48" {
    name = "Get emails"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_emails_46.id]
    position = {
      x = 1680.0
      y = -120.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"Authorization": "Bearer {{.CREDENTIAL.gmail_read_oauth }}"}, "method": "get", "payload": {"q": "in:inbox after:{{ \"now\" | date: \"%s\" | minus: 480 }}"}, "url": "https://www.googleapis.com/gmail/v1/users/phishing@tines.com/messages"})
}

resource "tines_agent" "get_email_by_id_49" {
    name = "Get email by id"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.read_mail_50.id]
    position = {
      x = 1680.0
      y = 90.0
    }
    agent_options = jsonencode({"headers": {"Authorization": "Bearer {{.CREDENTIAL.gmail_read_oauth }}"}, "method": "get", "payload": {"format": "raw"}, "url": "https://www.googleapis.com/gmail/v1/users/phishing@tines.com/messages/{{.explode_emails.email.id}}"})
}

resource "tines_agent" "read_mail_50" {
    name = "Read Mail"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 1680.0
      y = 165.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": "{{.get_email_by_id.body.raw | base64url_decode | eml_parse | as_object }}"})
}

resource "tines_agent" "build_results_51" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_33.id]
    position = {
      x = -45.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"all_results": "{% capture all_results %}{% for result in .implode_emails %}\n{% if result.analyze_email.malicious == \u0027true\u0027 %}\ntrue\n{% else %}\nfalse\n{% endif %}\n{% endfor %}{% endcapture %}{{all_results}}", "any_malicious": "{% if all_results contains \u0027true\u0027 %}true{% else %}false{% endif %}", "raw": "{{.implode_emails | as_object}}", "total_analyzed": "{{.implode_emails.size}}", "type": "email"}})
}

resource "tines_agent" "read_mail_52" {
    name = "Read Mail"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.analyze_headers_22.id]
    position = {
      x = 1290.0
      y = 645.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": "{{.receive_eml_file.body.upload_eml_file.contents | base64_decode | eml_parse | as_object}}"})
}

resource "tines_agent" "build_results_53" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_33.id]
    position = {
      x = 825.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"all_results": "{% capture all_results %}{% for result in .implode_url_array %}\n{% if result.analyze_url.malicious == \u0027true\u0027 or result.analyze_url_in_virustotal.malicious == \u0027true\u0027%}\ntrue\n{% else %}\nfalse\n{% endif %}\n{% endfor %}{% endcapture %}{{all_results}}", "any_malicious": "{% if all_results contains \u0027true\u0027 %}true{% else %}false{% endif %}", "raw": "{{.implode_attachments | as_object}}", "total_analyzed": "{{.implode_url_array.size}}", "type": "attachment"}})
}

resource "tines_agent" "build_results_54" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_analysis_33.id]
    position = {
      x = 1800.0
      y = 1440.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"all_results": "{% capture all_results %}{% for result in .implode_url_array %}\n{% if result.analyze_url.malicious == \u0027true\u0027 or result.analyze_url_in_virustotal.malicious == \u0027true\u0027%}\ntrue\n{% else %}\nfalse\n{% endif %}\n{% endfor %}{% endcapture %}{{all_results}}", "any_malicious": "{% if all_results contains \u0027true\u0027 %}true{% else %}false{% endif %}", "raw": "{{.implode_url_array | as_object}}", "total_analyzed": "{{.implode_url_array.size}}", "type": "url"}})
}

resource "tines_agent" "build_service_now_content_55" {
    name = "Build Service Now Content"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.prompt_response_18.id, tines_agent.update_case_20.id]
    position = {
      x = 750.0
      y = 1590.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"attachments": "{% assign attachment_results = .implode_analysis | where: \"build_results.type\", \u0027attachment\u0027 | map: \u0027build_results\u0027%}\n\n\u003ch2\u003e\u003cb\u003eAttachment Results\u003c/b\u003e\u003c/h2\u003e\u003cbr\u003e \n\n{% if attachment_results.first.total_analyzed == 0 %}\nNo Results Found\u003cbr\u003e\u003cbr\u003e\n\n{% else %}\n\n\u003ctable\u003e\n  \u003ctr\u003e\n    \u003cth\u003eFile Name\u003c/th\u003e\n    \u003cth\u003eHash\u003c/th\u003e\n    \u003cth\u003eHybridAnalysis Verdict\u003c/th\u003e\n    \u003cth\u003eVirusTotal Verdict\u003c/th\u003e\n    \u003cth\u003eNew\u003c/th\u003e\n    \u003cth\u003eResponse Actions\u003c/th\u003e\n  \u003c/tr\u003e\n{% for attachment in attachment_results.first.raw %}\n  \u003ctr\u003e\n    \u003ctd\u003e{{attachment.explode_attachments.individual_attachment.filename}}\u003c/td\u003e\n    \u003ctd\u003e{{attachment.explode_attachments.individual_attachment.sha256}}\u003c/td\u003e\n    \u003ctd\u003e\u003ca href=\"{{attachment.analyze_attachment.analysis_link | default: \u0027https://hybridanalysis.com\u0027}}\"\u003e{% if attachment.analyze_attachment.malicious == \u0027true\u0027%}\u274c Malicious{% else %}\u2705 Not Malicious{% endif %}\u003c/a\u003e\u003c/td\u003e\n    \u003ctd\u003e\u003ca href=\"{{attachment.analyze_attachment_in_virustotal.analysis_link | default: \u0027https://virustotal.com\u0027}}\"\u003e{% if attachment.analyze_attachment_in_virustotal.malicious == \u0027true\u0027%}\u274c Malicious{% else %}\u2705 Not Malicious{% endif %}\u003c/a\u003e\u003c/td\u003e\n    \u003ctd\u003e{{attachment.analyze_attachment.new }}\u003c/td\u003e\n    \u003ctd\u003e\u003ca href=\"https://tines.io\"\u003eBan Hash\u003c/a\u003e\u003c/td\u003e\n  \u003c/tr\u003e\n{% endfor %}\n\u003c/table\u003e\u003cbr\u003e\u003cbr\u003e\n\n{% endif %}", "body_emails": "{% assign email_results = .implode_analysis | where: \"build_results.type\", \u0027email\u0027 | map: \u0027build_results\u0027%}\n\n\u003ch2\u003e\u003cb\u003eEmail Analysis Results\u003c/b\u003e\u003c/h2\u003e\u003cbr\u003e\u003cbr\u003e\n \n{% if email_results.build_results.total_analyzed == 0 %}\nNo email addresses found in the mail body.\u003cbr\u003e\u003cbr\u003e\n{% else %}\n\n\u003ctable\u003e\n  \u003ctr\u003e\n    \u003cth\u003eEmail Address\u003c/th\u003e\n    \u003cth\u003eMalicious\u003c/th\u003e\n    \u003cth\u003eCEO Fraud\u003c/th\u003e\n    \u003cth\u003eBlacklisted\u003c/th\u003e\n    \u003cth\u003eSuspicious\u003c/th\u003e\n    \u003cth\u003eDisposable Email\u003c/th\u003e\n    \u003cth\u003eDomain Age\u003c/th\u003e\n  \u003c/tr\u003e\n{% for address in email_results.first.raw %}\n  \u003ctr\u003e\n    \u003ctd\u003e{{address.explode_email_array.individual_email}}\u003c/td\u003e\n    \u003ctd\u003e{% if .address.analyze_email.malicious == \u0027true\u0027 %}\u274c Malicious{% else %}\u2705 Not Malicious{% endif %}\u003c/td\u003e\n    \u003ctd\u003e{{address.analyze_email.ceo_fraud}}\u003c/td\u003e\n    \u003ctd\u003e{{address.analyze_email.email_blacklisted}}\u003c/td\u003e\n    \u003ctd\u003e{{address.analyze_email.suspicious_email}}\u003c/td\u003e\n    \u003ctd\u003e{{address.analyze_email.disposable_email}}\u003c/td\u003e\n    \u003ctd\u003e{{address.analyze_email.email_domain_age}}\u003c/td\u003e\n  \u003c/tr\u003e\n{% endfor %}\n\u003c/table\u003e\u003cbr\u003e\u003cbr\u003e\u003cbr\u003e\n\n{% endif %}", "headers": "{% if analyze_headers %}\n\u003ch2\u003e\u003cb\u003eHeader Analysis Results\u003c/b\u003e\u003c/h2\u003e\u003cbr\u003e\u003cbr\u003e\n\n\u003ctable\u003e\n  \u003ctr\u003e\n    \u003cth\u003eIP\u003c/th\u003e\n    \u003cth\u003eGeoLocation\u003c/th\u003e\n    \u003cth\u003eDMARC\u003c/th\u003e\n    \u003cth\u003eSPF\u003c/th\u003e\n    \u003cth\u003eDKIM\u003c/th\u003e\n    \u003cth\u003eASN\u003c/th\u003e\n    \u003cth\u003eRecent Spam Activity\u003c/th\u003e\n    \u003cth\u003eIP Reputation\u003c/th\u003e\n  \u003c/tr\u003e\n  \u003ctr\u003e\n    \u003ctd\u003e{{.analyze_headers.initial_ip}}\u003c/td\u003e\n    \u003ctd\u003e{{.analyze_headers.city}},{{.analyze_headers.country}}\u003c/td\u003e\n    \u003ctd\u003e{{.analyze_headers.dmarc}}\u003c/td\u003e\n    \u003ctd\u003e{{.analyze_headers.spf}}\u003c/td\u003e\n    \u003ctd\u003e{{.analyze_headers.dkim}}\u003c/td\u003e\n    \u003ctd\u003e{{.analyze_headers.organization}}\u003c/td\u003e\n    \u003ctd\u003e{{.analyze_headers.recent_spam_activity}}\u003c/td\u003e\n    \u003ctd\u003e{{.analyze_headers.ip_sender_reputation}}\u003c/td\u003e\n  \u003c/tr\u003e\n\u003c/table\u003e\u003cbr\u003e\u003cbr\u003e\n\n\n{% endif %}\n\n\n", "sender_email": "{% assign sender_results = .implode_analysis | where: \"build_results.type\", \u0027sender\u0027 | map: \u0027build_results\u0027%}\n\n\u003ch2\u003e\u003cb\u003eSender Analysis Results\u003c/b\u003e\u003c/h2\u003e\u003cbr\u003e\u003cbr\u003e\n\n\u003ctable\u003e\n  \u003ctr\u003e\n    \u003cth\u003eEmail Address\u003c/th\u003e\n    \u003cth\u003eMalicious\u003c/th\u003e\n    \u003cth\u003eCEO Fraud\u003c/th\u003e\n    \u003cth\u003eBlacklisted\u003c/th\u003e\n    \u003cth\u003eSuspicious\u003c/th\u003e\n    \u003cth\u003eDisposable Email\u003c/th\u003e\n    \u003cth\u003eDomain Age\u003c/th\u003e\n  \u003c/tr\u003e\n  \u003ctr\u003e\n    \u003ctd\u003e{{.sender_results.first.raw.email_address}}\u003c/td\u003e\n    \u003ctd\u003e{% if .sender_results.first.raw.malicious == true %}\u274c Malicious{% else %}\u2705 Not Malicious{% endif %}\u003c/td\u003e\n    \u003ctd\u003e{{.sender_results.first.raw.ceo_fraud}}\u003c/td\u003e\n    \u003ctd\u003e{{.sender_results.first.raw.email_blacklisted}}\u003c/td\u003e\n    \u003ctd\u003e{{.sender_results.first.raw.suspicious_email}}\u003c/td\u003e\n    \u003ctd\u003e{{.sender_results.first.raw.disposable_email}}\u003c/td\u003e\n    \u003ctd\u003e{{.sender_results.first.raw.email_domain_age}}\u003c/td\u003e\n  \u003c/tr\u003e\n\u003c/table\u003e\u003cbr\u003e\u003cbr\u003e", "summary": "\u003ca href=\"{% story_run_link %}\"\u003eTines Event Link\u003c/a\u003e\u003cbr\u003e\u003cbr\u003e\n{% assign all_results = .implode_analysis | jsonpath: \u0027*.build_results.any_malicious\u0027 %}\n\u003ch2\u003e\u003cb\u003eOverall Classification:\u003c/b\u003e {% if all_results contains \"true\" %}\u003cb\u003e\u274c MALICIOUS\u003c/b\u003e {% else %}} \u003cb\u003e\u2705 Not Malicious\u003c/b\u003e {% endif %}\u003c/h2\u003e\u003cbr\u003e\n\u003ca href=\"{% prompt contain %}\"\u003eClick here to contain this device in Crowdstrike\u003c/a\u003e\u003cbr\u003e\u003cbr\u003e\n\u003ch2\u003e\u003cb\u003eDetailed analysis results for this email can be found below\u003c/b\u003e\u003c/h2\u003e\u003cbr\u003e\u003cbr\u003e", "urls": "{% assign url_results = .implode_analysis | where: \"build_results.type\", \u0027url\u0027 | map: \u0027build_results\u0027%}\n\n\u003ch2\u003e\u003cb\u003eURL Analysis Results\u003c/b\u003e\u003c/h2\u003e\u003cbr\u003e\n{% if url_results.first.total_analyzed == 0 %}}\nNo URLs found in this mail\u003cbr\u003e\n{% else %}\n\n\u003ctable\u003e\n  \u003ctr\u003e\n    \u003cth\u003eURL\u003c/th\u003e\n    \u003cth\u003eURLScan Verdict\u003c/th\u003e\n    \u003cth\u003eAnalysis Date\u003c/th\u003e\n    \u003cth\u003eVirustotal Verdict\u003c/th\u003e\n    \u003cth\u003eResponse Actions\u003c/th\u003e\n  \u003c/tr\u003e\n{% for url in url_results.first.raw %}\n  \u003ctr\u003e\n    \u003ctd\u003e{{url.explode_urls.individual_url | regex_replace: \u0027https?://\u0027, \u0027hxxps?//\u0027 | replace: \u0027.\u0027, \u0027[.]\u0027}}\u003c/td\u003e\n    \u003ctd\u003e\u003ca href=\"{{url.analyze_url.analysis_link | default: \u0027https://urlscan.io\u0027}}\"\u003e{% if url.analyze_url.malicious == \u0027true\u0027%}\u274c Malicious{% else %}\u2705 Not Malicious{% endif %}\u003c/a\u003e\u003c/td\u003e\n    \u003ctd\u003e{{url.analyze_url.analysis_date}}\u003c/td\u003e\n    \u003ctd\u003e\u003ca href=\"{{url.analyze_url_in_virustotal.analysis_link | default: \u0027https://virustotal.com\u0027}}\"\u003e{% if url.analyze_url_in_virustotal.malicious == \u0027true\u0027%}\u274c Malicious{% else %}\u2705 Not Malicious{% endif %}\u003c/a\u003e\u003c/td\u003e\n    \u003ctd\u003e\u003ca href=\"https://tines.io\"\u003eBlock Domain\u003c/a\u003e\u003c/td\u003e\n  \u003c/tr\u003e\n{% endfor %}\n\u003c/table\u003e\u003cbr\u003e\u003cbr\u003e\u003cbr\u003e\n\n{% endif %}"}})
}

resource "tines_agent" "create_new_incident_ticket_in_servicenow_56" {
    name = "Create New Incident Ticket in ServiceNow"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.check_for_attachments_8.id, tines_agent.analyze_sender_24.id, tines_agent.check_for_emails_in_body_26.id, tines_agent.check_for_urls_44.id]
    position = {
      x = 735.0
      y = 795.0
    }
    agent_options = jsonencode({"basic_auth": "admin:{{ .CREDENTIAL.servicenow }}", "content_type": "json", "method": "post", "payload": {"comments": "[code]\u003ch2\u003eSummary\u003c/h2\u003e\u003cbr\u003e\n\u003cb\u003eFrom:\u003c/b\u003e {{.read_mail.from}} \u003cbr\u003e\n\u003cb\u003eTo:\u003c/b\u003e {{.read_mail.to}} \u003cbr\u003e\n\u003cb\u003eSubject:\u003c/b\u003e {{.read_mail.subject}} \u003cbr\u003e\n\u003cb\u003eDate:\u003c/b\u003e {{.read_mail.date}} \u003cbr\u003e\n\u003cb\u003eBody:\u003c/b\u003e\u003cbr\u003e\u003cbr\u003e\n\n\u003ccode\u003e\n{{.read_mail.body | replace: \u0027\n\u0027, \u0027\u003cbr\u003e\u0027}}\n\u003c/code\u003e\u003cbr\u003e\u003cbr\u003e\n\n\u003ch2\u003eAttachments\u003c/h2\u003e \u003cbr\u003e\n\n\u003ctable style=\"width:100%\"\u003e\n  \u003ctr\u003e\n    \u003cth\u003eName\u003c/th\u003e\n    \u003cth\u003eSize (Bytes)\u003c/th\u003e\n    \u003cth\u003eSHA256 Hash\u003c/th\u003e\n  \u003c/tr\u003e\n{% for attachment in read_mail.attachments %}\n  \u003ctr\u003e\n    \u003ctd\u003e{{attachment.filename}}\u003c/td\u003e\n    \u003ctd\u003e{{attachment.sizeinbytes}}\u003c/td\u003e\n    \u003ctd\u003e{{attachment.sha256}}\u003c/td\u003e\n  \u003c/tr\u003e\n{% endfor %}\n\u003c/table\u003e\u003cbr\u003e\u003cbr\u003e\n[/code]\n", "short_description": "New Email Reported from {{.add_reporter.reporter | default: .read_mail.from}}"}, "url": "https://{{.RESOURCE.servicenowdomain }}/api/now/v1/table/incident"})
}

resource "tines_agent" "update_servicenow_incident_57" {
    name = "Update ServiceNow Incident"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 750.0
      y = 1755.0
    }
    agent_options = jsonencode({"basic_auth": "admin:{{ .CREDENTIAL.servicenow }}", "content_type": "json", "method": "put", "payload": {"comments": "[code]\n{{.build_service_now_content.summary }}\n\n{{.build_service_now_content.urls }}\n\n{{.build_service_now_content.attachments }}\n\n{{.build_service_now_content.body_emails }}\n\n{{.build_service_now_content.sender_email }}\n\n{{.build_service_now_content.headers }}\n\n[/code]"}, "url": "https://{{.RESOURCE.servicenowdomain}}/api/now/v1/table/incident/{{.create_new_incident_ticket_in_servicenow.body.result.sys_id }}?sysparm_exclude_ref_link=true"})
}

resource "tines_agent" "upload_attachment_to_service_now_case_58" {
    name = "Upload Attachment to Service Now Case"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 2055.0
      y = 1350.0
    }
    agent_options = jsonencode({"basic_auth": "admin:{{ .CREDENTIAL.servicenow }}", "content_type": "json", "method": "post", "payload": {"data-binary": "{{.analyze_url.screenshot.contents | base64_decode }}"}, "url": "https://{{.RESOURCE.servicenowurl}}/api/now/attachment/file?table_name=incident\u0026table_sys_id={{ \n.create_new_incident_ticket_in_servicenow.body.result.sys_id }}\u0026file_name={{.analyze_url.url | replace: \u0027.\u0027, \u0027_\u0027 }}"})
}

resource "tines_note" "note_0" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
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

resource "tines_note" "note_1" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
IMAP Action

The IMAP action will connect to a mailbox where the mailserver is configured to have IMAP enabled.

Enter the mailserver, the username and the password to connect any begin reading mails.

The first time this Action is run, the mailbox state will be recorded and any future mails will be read into Tines on subsequent Action queries.
EOF
    position = {
      x = 540.0
      y = 75.0
    }
}

resource "tines_note" "note_2" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
Analyzing Emails

In cases where the internal users reports the email by forwarding it inline, rather than as an attachment, we will want to check the body for any email addresses found, and check the reputation of these individually.
EOF
    position = {
      x = -615.0
      y = 975.0
    }
}

resource "tines_note" "note_3" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
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

resource "tines_note" "note_4" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
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

resource "tines_note" "note_5" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
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

resource "tines_note" "note_6" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
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

resource "tines_note" "note_7" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
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

resource "tines_note" "note_8" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
Parsing the Mail

The array of email IDs is being exploded into individual events so we can handle each mail by itself.

The Dedup Action will ensure that each mail is only examined once.

Next, using the original mail ID we can get the raw Base64Encoded Email Body, which we will then parse into the regular email format.

EOF
    position = {
      x = 1890.0
      y = 30.0
    }
}

resource "tines_note" "note_9" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
Reading Mails with GSuite

The first Action here will connect to the GMail API and retrieve a list of all mails received in the past 8 minutes or so. This Action should be scheduled to run every 5 minutes or so. The overlap between the schedule time, and the lookback time will ensure a mail does not get missed.

This Action uses an OAuth Token belonging to the Mailbox we're reading. This can also be a Service Account JWT Token, if necessary.
EOF
    position = {
      x = 1395.0
      y = -225.0
    }
}

resource "tines_note" "note_10" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
Creating Incident Ticket

Before any email content is analyzed we can create an issue in the security case management system.
This will contain basic mail info such as subject, body, and headers.
EOF
    position = {
      x = 360.0
      y = 705.0
    }
}

resource "tines_note" "note_11" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
Handling Prompts

We are adding a couple of Trigger Actions here to handle Prompt Responses. If there is a Prompt included in The Hive incident - for example to Contain the Device in Crowdstrike - then these Actions will route the response to the right place.
EOF
    position = {
      x = 1290.0
      y = 1725.0
    }
}

resource "tines_note" "note_12" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
Tying Everything Together

This Implode Action will wait for all previous analysis to complete, and bring everything together in one event so we can prepare the results.
EOF
    position = {
      x = 990.0
      y = 1515.0
    }
}

resource "tines_note" "note_13" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
Updating Service Now

We're next going to post a new comment to the Service Now case to include:

- An overall verdict on the mail
- The initial case description including mail body and headers
- Attachment, URL, Sender and Email analysis

EOF
    position = {
      x = 510.0
      y = 1845.0
    }
}

resource "tines_note" "note_14" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
Imploding and Building Results

The Implode Action will wait until all URLs have been analyzed and results returned. It will then merge these results into one event which will be available later.

Build Results will summarise the results of URL analysis and indicate whether any of the URLs were malicious, and how many URLs were analyzed in total.
EOF
    position = {
      x = 1860.0
      y = 1500.0
    }
}

resource "tines_note" "note_15" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
Analyzing Sender

To check the reputation of the sender of the suspicious email it is submitted to a Tines Sub-Story which will analyze the email address and return the results to this story.
EOF
    position = {
      x = 1305.0
      y = 1005.0
    }
}

resource "tines_note" "note_16" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
EML Handling

Some users or report phish buttons will forward the suspicious email as a .eml attachment.

In these cases, we want to identify these attachments and analyze this eml file including email headers.
EOF
    position = {
      x = 1290.0
      y = 330.0
    }
}

resource "tines_note" "note_17" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
Presenting the Results

In the Build Service Now Content Action we are going to build Service Now formatted content that the analyst will actually review.
The 'assign' block in this action is looking in the event output from Implode Analysis for the relevant analysis 'type'; URL, Attachment, Email, or Sender.
Any additions, or updates needed in the Service Now case can be modified in this action.

EOF
    position = {
      x = 450.0
      y = 1545.0
    }
}

resource "tines_note" "note_18" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
Analyzing URLs

Any URLs found in the body of the email are identified and extracted.

We're then exploding the array of extracted URLs so that we can look at these URLs individually.

Each URL will be analyzed by URLScan and VirusTotal. 
If a URL is identified as malicious, it will be added to TheHive case as an observable.

EOF
    position = {
      x = 2040.0
      y = 1065.0
    }
}

resource "tines_note" "note_19" {
    story_id = tines_story.spam_analysis_new_-_servicenow.id
    content = <<EOF
Uploading Attachments

A screenshot of each of the scanned URLs is created by URLScan.

Here we can attach each of those screenshots to the ServiceNow case for analysts to review if needed.

This process can be applied for any file that should be uploaded.
EOF
    position = {
      x = 2295.0
      y = 1350.0
    }
}
