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

resource "tines_story" "sts_analyze_email_address" {
    name = "STS Analyze Email Address"
    team_id = var.team_id
    description = <<EOF
Substory to Analyze an Email Address
EOF
}


resource "tines_agent" "webhook_agent_0" {
    name = "Webhook Agent"
    agent_type = "Agents::WebhookAgent"
    story_id = tines_story.sts_analyze_email_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.extract_domain_2.id]
    position = {
      x = 225.0
      y = -660.0
    }
    agent_options = jsonencode({"include_headers": "false", "secret": "2ee4909bd3c7357972fd0d1567c72d63", "verbs": "get,post"})
}

resource "tines_agent" "check_if_knowngood_1" {
    name = "Check if Knowngood"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.sts_analyze_email_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_not_knowngood_4.id, tines_agent.trigger_if_knowngood_8.id]
    position = {
      x = 225.0
      y = -510.0
    }
    agent_options = jsonencode({"emit_no_match": "true", "rules": [{"path": "{{ .extract_domain.email_domain.first.first }}", "type": "field==value", "value": "tines.io"}]})
}

resource "tines_agent" "extract_domain_2" {
    name = "Extract Domain"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.sts_analyze_email_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.check_if_knowngood_1.id]
    position = {
      x = 225.0
      y = -585.0
    }
    agent_options = jsonencode({"matchers": [{"path": "{{.webhook_agent.emailaddress}}", "regexp": "@(.*\\.*)", "to": "email_domain"}], "mode": "extract"})
}

resource "tines_agent" "get_email_reputation_3" {
    name = "Get Email Reputation"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_analyze_email_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_6.id]
    position = {
      x = 225.0
      y = -270.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"Key": "{% credential emailrep %}"}, "log_error_on_status": [], "method": "get", "payload": {}, "url": "https://emailrep.io/{{.webhook_agent.emailaddress}}"})
}

resource "tines_agent" "trigger_if_not_knowngood_4" {
    name = "Trigger if Not Knowngood"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.sts_analyze_email_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.regex_for_ceo_fraud_5.id]
    position = {
      x = 495.0
      y = -435.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .check_if_knowngood.rule_matched }}", "type": "regex", "value": "false"}]})
}

resource "tines_agent" "regex_for_ceo_fraud_5" {
    name = "Regex for CEO Fraud"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.sts_analyze_email_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.get_email_reputation_3.id]
    position = {
      x = 495.0
      y = -345.0
    }
    agent_options = jsonencode({"emit_no_match": "true", "rules": [{"path": "{{ .webhook_agent.emailaddress }}", "type": "regex", "value": "^[EeOo].{1,3}n.{0,5}[Hh].{1,3}n.{0,5}y|^[EeOo].{1,3}n@[Tt].{1,3}n.{1,3}s"}]})
}

resource "tines_agent" "build_results_6" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.sts_analyze_email_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 225.0
      y = -195.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"ceo_fraud": "{% if trigger_if_knowngood %}false{% else %}{{.regex_for_ceo_fraud.rule_matched}}{% endif %}", "disposable_email": "{% if get_email_reputation.status == 500 %}error{% else %}{{.get_email_reputation.body.details.disposable}}{% endif %}", "email_address": "{{.webhook_agent.emailaddress}}", "email_blacklisted": "{% if trigger_if_knowngood %}false{% elsif get_email_reputation.status == 500 %}error{% else %}{{.get_email_reputation.body.details.blacklisted}}{% endif %}", "email_domain_age": "{% if get_email_reputation.status == 500 %}error{% else %}{{.get_email_reputation.body.details.days_since_domain_creation}}{% endif %}", "malicious": "{% if regex_for_ceo_fraud.rule_matched == true %}true{% elsif get_email_reputation.body.suspicious == true %}true{% elsif get_email_reputation.body.details.blacklisted == true %}true{% else %}false{% endif %}", "suspicious_email": "{% if trigger_if_knowngood %}false{% elsif get_email_reputation.status == 500 %}error{% else %}{{.get_email_reputation.body.suspicious}}{% endif %}"}})
}

resource "tines_agent" "send_to_story_agent_7" {
    name = "Send To Story Agent"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.sts_analyze_email_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 465.0
      y = -660.0
    }
    agent_options = jsonencode({"payload": {"emailaddress": "eoinhinchy@mailinator.com"}, "send_payload_as_body": "false", "story": "{% story STS Analyze Email Address %}"})
}

resource "tines_agent" "trigger_if_knowngood_8" {
    name = "Trigger if Knowngood"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.sts_analyze_email_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.get_email_reputation_3.id]
    position = {
      x = 225.0
      y = -435.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .check_if_knowngood.rule_matched }}", "type": "regex", "value": "true"}]})
}
