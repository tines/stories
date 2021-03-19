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

resource "tines_story" "sts_check_vips" {
    name = "STS Check VIPs"
    team_id = var.team_id
    description = <<EOF
 Trigger in array and in global resource
EOF
}


resource "tines_global_resource" "vip_list" {
    name = "vip_list"
    value_type = "text"
    value = "replaceme"
}

resource "tines_agent" "return_results_0" {
    name = "Return Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.sts_check_vips.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 615.0
      y = 615.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"false": "{{.implode_an_array | where: \u0027vip_check.rule_matched\u0027, false | jsonpath: \u0027*.individual_recipient\u0027 | as_object }}", "is_vip": "{{.trigger_if_any_vips.rule_matched}}", "true": "{{.implode_an_array | where: \u0027vip_check.rule_matched\u0027, true | jsonpath: \u0027*.individual_recipient\u0027 | as_object }}"}})
}

resource "tines_agent" "vip_check_1" {
    name = "VIP Check"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.sts_check_vips.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.implode_an_array_2.id]
    position = {
      x = 615.0
      y = 330.0
    }
    agent_options = jsonencode({"emit_no_match": "true", "rules": [{"path": "{{.explode_recipients.individual_recipient | downcase }}", "type": "in", "value": "{{.RESOURCE.vip_list | as_object}}"}]})
}

resource "tines_agent" "implode_an_array_2" {
    name = "Implode an Array"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.sts_check_vips.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_any_vips_3.id]
    position = {
      x = 615.0
      y = 435.0
    }
    agent_options = jsonencode({"guid_path": "{{.explode_recipients.guid}}", "mode": "implode", "size_path": "{{.explode_recipients.size}}"})
}

resource "tines_agent" "trigger_if_any_vips_3" {
    name = "Trigger if any VIPs"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.sts_check_vips.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.return_results_0.id]
    position = {
      x = 615.0
      y = 525.0
    }
    agent_options = jsonencode({"emit_no_match": "true", "rules": [{"path": "{{.implode_an_array | jsonpath: \u0027*.rule_matched\u0027 | as_object }}", "type": "in", "value": true}]})
}

resource "tines_agent" "get_email_address_4" {
    name = "Get Email Address"
    agent_type = "Agents::WebhookAgent"
    story_id = tines_story.sts_check_vips.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.explode_recipients_5.id]
    position = {
      x = 615.0
      y = 150.0
    }
    agent_options = jsonencode({"secret": "615b31c7845b62f92d312134fd1fd2c5", "verbs": "get,post"})
}

resource "tines_agent" "explode_recipients_5" {
    name = "Explode Recipients"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.sts_check_vips.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.vip_check_1.id]
    position = {
      x = 615.0
      y = 240.0
    }
    agent_options = jsonencode({"mode": "explode", "path": "{{.get_email_address.body.email}}", "to": "individual_recipient"})
}

resource "tines_agent" "send_to_story_agent_6" {
    name = "Send to Story Agent"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.sts_check_vips.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 330.0
      y = 150.0
    }
    agent_options = jsonencode({"payload": {"email": ["thomas@tines.io", "eoin@tines.io"]}, "story": "{% story STS Check VIPs %}"})
}
