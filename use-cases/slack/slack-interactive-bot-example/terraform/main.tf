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

resource "tines_story" "slack_interactive_bot_example" {
    name = "Slack Interactive Bot Example"
    team_id = var.team_id
    description = <<EOF
Demo Story for handling Slack Interactive Responses

To test this Story, either Run the Agent called "Run to kick off test", or submit a form.
This Jira ticket can be used for testing: https://tinesio.atlassian.net/browse/DEMO-2558


When enabling a Slack App to allow Interactive Content, a single Webhook URL must be provided. This webhook will receive all interactive responses related to this Slack App. 


This story will take a given email address, and send that user a custom message with the option to confirm or deny that action.
If the user denies the action, then a Jira ticket will be updated noting this response.
If a user confirms the action, they will be presented with a modal view allowing them to add some extra context about the action taken. Once submitted, the Jira ticket will be updated with the additional information. If the user closes this dialog before submitting a response, the Jira ticket will be updated to include that detail.

After either submitting a response, or denying the activity, the original Slack message will be overwritten with a message confirming the response and providing the Incident ID.


EOF
}


resource "tines_global_resource" "jira_svc_user" {
    name = "jira_svc_user"
    value_type = "text"
    value = "replaceme"
}

resource "tines_global_resource" "jira_domain" {
    name = "jira_domain"
    value_type = "text"
    value = "replaceme"
}

resource "tines_agent" "receive_interactive_from_slack_0" {
    name = "Receive Interactive From Slack"
    agent_type = "Agents::WebhookAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_modal_cancelled_4.id, tines_agent.trigger_if_block_action_response_13.id, tines_agent.trigger_if_modal_response_15.id]
    position = {
      x = 285.0
      y = 150.0
    }
    agent_options = jsonencode({"response": "", "secret": "83e5cd5a2a00a942e9ebc18b03d66ab6", "verbs": "get,post"})
}

resource "tines_agent" "send_message_to_user_in_slack_to_confirm_1" {
    name = "Send message to user in Slack to confirm"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = -450.0
      y = 330.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"Authorization": "Bearer {{.CREDENTIAL.slack_interactive_bot_token}}"}, "log_error_on_status": [], "method": "post", "payload": {"blocks": [{"block_id": "header_text", "text": {"text": "*Information Security Alert*", "type": "mrkdwn"}, "type": "section"}, {"block_id": "message_text", "fields": [{"text": "{{.receive_form.body.message}}", "type": "mrkdwn"}], "type": "section"}, {"block_id": "send_message_to_user", "elements": [{"action_id": "confirm", "style": "primary", "text": {"emoji": true, "text": "This Was Me", "type": "plain_text"}, "type": "button", "value": "-----{\"incident_id\": \"{{.receive_form.body.incident_id}}\",\"incident_type\": \"{{.receive_form.body.incident_type}}\",\"username\": \"{{.receive_form.body.email}}\", \"slack_id\": \"{{.search_user_by_email_in_slack.body.user.id}}\"}"}, {"action_id": "deny", "style": "danger", "text": {"emoji": true, "text": "I don\u0027t recognize this", "type": "plain_text"}, "type": "button", "value": "-----{\"incident_id\": \"{{.receive_form.body.incident_id}}\",\"incident_type\": \"{{.receive_form.body.incident_type}}\",\"username\": \"{{.receive_form.body.email}}\", \"slack_id\": \"{{.search_user_by_email_in_slack.body.user.id}}\"}"}], "type": "actions"}], "channel": "{{.search_user_by_email_in_slack.body.user.id}}", "text": "{{.receive_form.body.message}}"}, "url": "https://slack.com/api/chat.postMessage"})
}

resource "tines_agent" "search_user_by_email_in_slack_2" {
    name = "Search User by Email in Slack"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.send_message_to_user_in_slack_to_confirm_1.id]
    position = {
      x = -450.0
      y = 240.0
    }
    agent_options = jsonencode({"content_type": "json", "expected_update_period_in_days": "1", "headers": {"Authorization": "Bearer {{.CREDENTIAL.slack_interactive_bot_token}}"}, "log_error_on_status": [], "method": "get", "payload": {"email": "{{.receive_form.body.email}}"}, "url": "https://slack.com/api/users.lookupByEmail"})
}

resource "tines_agent" "receive_form_3" {
    name = "Receive Form"
    agent_type = "Agents::WebhookAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.search_user_by_email_in_slack_2.id]
    position = {
      x = -450.0
      y = 165.0
    }
    agent_options = jsonencode({"secret": "e8327186a21087d109ceee0111b99588", "verbs": "get,post"})
}

resource "tines_agent" "trigger_if_modal_cancelled_4" {
    name = "Trigger if Modal Cancelled"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.parse_response_6.id]
    position = {
      x = 585.0
      y = 240.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.receive_interactive_from_slack.body.payload}}", "type": "regex", "value": "dialog_cancellation|view_closed"}]})
}

resource "tines_agent" "request_more_info_modal_5" {
    name = "Request More Info Modal"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = -150.0
      y = 555.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"Authorization": "Bearer {{.CREDENTIAL.slack_interactive_bot_token}}"}, "log_error_on_status": [], "method": "post", "payload": {"trigger_id": "{{.parse_response.response.trigger_id}}", "view": {"blocks": [{"block_id": "\"{{.parse_response.response.message.ts}}\",{{.parse_response.response.channel.id}}", "text": {"emoji": true, "text": "Thank you for confirming this action. \nTo help the Information Security team resolve this incident, please provide some details of the action taken, and the reasoning for this.", "type": "plain_text"}, "type": "section"}, {"block_id": "summary_textbox_block", "element": {"action_id": "response_summary", "multiline": true, "type": "plain_text_input"}, "label": {"emoji": true, "text": "Summary", "type": "plain_text"}, "type": "input"}, {"type": "divider"}, {"block_id": "radio_button_block", "element": {"action_id": "radio-action", "options": [{"text": {"text": "I would like Information Security to contact me regarding this incident.", "type": "mrkdwn"}, "value": "confirm_contact"}, {"text": {"text": "No need to contact me, this should clear it up.", "type": "mrkdwn"}, "value": "reject_contact"}], "type": "radio_buttons"}, "label": {"emoji": true, "text": "Follow-Up", "type": "plain_text"}, "type": "input"}], "notify_on_close": "true", "private_metadata": "{{.parse_response.response.actions.first.value}}", "submit": {"text": "Submit", "type": "plain_text"}, "title": {"text": "Additional Information", "type": "plain_text"}, "type": "modal"}}, "url": "https://slack.com/api/views.open"})
}

resource "tines_agent" "parse_response_6" {
    name = "Parse Response"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.parse_incident_information_7.id]
    position = {
      x = 585.0
      y = 330.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"response": "{{.receive_interactive_from_slack.body.payload | json_parse | as_object}}"}})
}

resource "tines_agent" "parse_incident_information_7" {
    name = "Parse Incident Information"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.add_comment_to_jira_ticket_23.id]
    position = {
      x = 585.0
      y = 405.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"incident_data": "{{.parse_response.response.view.private_metadata | replace: \u0027-----\u0027 | json_parse | as_object}}"}})
}

resource "tines_agent" "parse_response_8" {
    name = "Parse Response"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_user_response_12.id]
    position = {
      x = -150.0
      y = 330.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"response": "{{.receive_interactive_from_slack.body.payload | replace: \u0027\\\"{\u0027, \u0027{\u0027 | replace: \u0027}\\\"\u0027, \u0027}\u0027 | json_parse | as_object}}"}})
}

resource "tines_agent" "parse_response_9" {
    name = "Parse Response"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.parse_incident_information_14.id]
    position = {
      x = 285.0
      y = 330.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"response": "{{.receive_interactive_from_slack.body.payload | json_parse | as_object}}"}})
}

resource "tines_agent" "user_denied_10" {
    name = "User Denied"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.parse_incident_information_21.id]
    position = {
      x = 60.0
      y = 495.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.parse_response.response.actions.first.action_id}}", "type": "field==value", "value": "deny"}]})
}

resource "tines_agent" "user_confirmed_11" {
    name = "User Confirmed"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.request_more_info_modal_5.id]
    position = {
      x = -150.0
      y = 495.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.parse_response.response.actions.first.action_id}}", "type": "field==value", "value": "confirm"}]})
}

resource "tines_agent" "trigger_if_user_response_12" {
    name = "Trigger if User Response"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.user_denied_10.id, tines_agent.user_confirmed_11.id]
    position = {
      x = -150.0
      y = 405.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.parse_response.response.actions.first.block_id}}", "type": "field==value", "value": "send_message_to_user"}]})
}

resource "tines_agent" "trigger_if_block_action_response_13" {
    name = "Trigger if Block Action Response"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.parse_response_8.id]
    position = {
      x = -150.0
      y = 240.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.receive_interactive_from_slack.body.payload}}", "type": "regex", "value": "block_actions"}]})
}

resource "tines_agent" "parse_incident_information_14" {
    name = "Parse Incident Information"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.update_message_19.id]
    position = {
      x = 285.0
      y = 405.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"incident_data": "{{.parse_response.response.view.private_metadata | replace: \u0027-----\u0027 | json_parse | as_object}}", "response_metadata": "{{.parse_response.response.view.blocks.first.block_id | split: \u0027,\u0027 | as_object}}"}})
}

resource "tines_agent" "trigger_if_modal_response_15" {
    name = "Trigger if Modal Response"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.parse_response_9.id]
    position = {
      x = 285.0
      y = 240.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{.receive_interactive_from_slack.body.payload}}", "type": "regex", "value": "view_submission"}]})
}

resource "tines_agent" "run_to_kick_off_test_16" {
    name = "Run to kick off test"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.receive_form_17.id]
    position = {
      x = -735.0
      y = 90.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {}, "method": "get", "payload": {}, "url": "http://www.tines.io"})
}

resource "tines_agent" "receive_form_17" {
    name = "Receive Form"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.search_user_by_email_in_slack_2.id]
    position = {
      x = -735.0
      y = 165.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"body": {"email": "thomas@tines.io", "incident_id": "DEMO-2558", "incident_type": "phishing", "message": "This is a test message"}}})
}

resource "tines_agent" "update_message_18" {
    name = "Update Message"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.add_comment_to_jira_ticket_20.id]
    position = {
      x = 60.0
      y = 660.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"Authorization": "Bearer {{.CREDENTIAL.slack_interactive_bot_token}}"}, "log_error_on_status": [], "method": "post", "payload": {"attachments": [], "channel": "{{.parse_response.response.channel.id}}", "text": "Thank you for your response - a member of the Security team will be in touch with further guidance.\nThe Incident ID for this alert is *{{.parse_incident_information.incident_data.incident_id}}*", "ts": "\"{{.parse_response.response.message.ts}}\""}, "url": "https://slack.com/api/chat.update"})
}

resource "tines_agent" "update_message_19" {
    name = "Update Message"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.add_comment_to_jira_ticket_22.id]
    position = {
      x = 285.0
      y = 495.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"Authorization": "Bearer {{.CREDENTIAL.slack_interactive_bot_token}}"}, "log_error_on_status": [], "method": "post", "payload": {"attachments": [], "blocks": [{"block_id": "header_text", "text": {"text": "Thank you, your response has been recorded.\nIf you need to contact the Information Security Team regarding this alert, please quote the Incident ID: *{{.parse_incident_information.incident_data.incident_id}}*", "type": "mrkdwn"}, "type": "section"}], "channel": "{{.parse_incident_information.response_metadata.last}}", "text": "Your response has been received.", "ts": "{{.parse_incident_information.response_metadata.first}}"}, "url": "https://slack.com/api/chat.update"})
}

resource "tines_agent" "add_comment_to_jira_ticket_20" {
    name = "Add Comment to Jira Ticket"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 60.0
      y = 735.0
    }
    agent_options = jsonencode({"basic_auth": ["{{.RESOURCE.jira_svc_user}}", "{{.CREDENTIAL.jira_svc_pwd}}"], "content_type": "json", "method": "post", "payload": {"body": "The user has indicated that they did not carry out this activity.\nResponse time: {{\u0027now\u0027 | date: \u0027%e %b %Y %H:%M:%S%p\u0027}}"}, "url": "https://{{ .RESOURCE.jira_domain }}/rest/api/2/issue/{{.parse_incident_information.incident_data.incident_id}}/comment/"})
}

resource "tines_agent" "parse_incident_information_21" {
    name = "Parse Incident Information"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.update_message_18.id]
    position = {
      x = 60.0
      y = 570.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"incident_data": "{{.parse_response.response.actions.first.value | replace: \u0027-----\u0027 | json_parse | as_object}}"}})
}

resource "tines_agent" "add_comment_to_jira_ticket_22" {
    name = "Add Comment to Jira Ticket"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 285.0
      y = 570.0
    }
    agent_options = jsonencode({"basic_auth": ["{{.RESOURCE.jira_svc_user}}", "{{.CREDENTIAL.jira_svc_pwd}}"], "content_type": "json", "method": "post", "payload": {"body": "The user has indicated that they did carry out this activity, and has included this context:\n\nbq. {{.parse_response.response.view.state.values.summary_textbox_block.response_summary.value}} \n\nResponse time: {{\u0027now\u0027 | date: \u0027%e %b %Y %H:%M:%S%p\u0027}}"}, "url": "https://{{ .RESOURCE.jira_domain }}/rest/api/2/issue/{{.parse_incident_information.incident_data.incident_id}}/comment/"})
}

resource "tines_agent" "add_comment_to_jira_ticket_23" {
    name = "Add Comment to Jira Ticket"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.slack_interactive_bot_example.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 585.0
      y = 495.0
    }
    agent_options = jsonencode({"basic_auth": ["{{.RESOURCE.jira_svc_user}}", "{{.CREDENTIAL.jira_svc_pwd}}"], "content_type": "json", "method": "post", "payload": {"body": "The user indicated they did carry out this activity, but closed or cancelled the response window before submitting any extra context.\n\nResponse time: {{\u0027now\u0027 | date: \u0027%e %b %Y %H:%M:%S%p\u0027}}"}, "url": "https://{{ .RESOURCE.jira_domain }}/rest/api/2/issue/{{.parse_incident_information.incident_data.incident_id}}/comment/"})
}
