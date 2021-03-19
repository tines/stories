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

resource "tines_story" "sts_analyze_ip_address" {
    name = "STS Analyze IP Address"
    team_id = var.team_id
    description = <<EOF

EOF
}


resource "tines_global_resource" "jira_domain" {
    name = "jira_domain"
    value_type = "text"
    value = "replaceme"
}

resource "tines_agent" "check_ip_reputation_using_apivoid_0" {
    name = "Check IP Reputation using APIVoid"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.search_for_ip_address_in_abuse_ipdb_7.id]
    position = {
      x = 105.0
      y = -435.0
    }
    agent_options = jsonencode({"content_type": "json", "log_error_on_status": [], "method": "get", "payload": {"ip": "{{.webhook_agent.body.ipaddress}}", "key": "{% credential apivoid %}"}, "url": "https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/"})
}

resource "tines_agent" "get_tor_nodes_1" {
    name = "Get Tor Nodes"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_tor_node_4.id]
    position = {
      x = 105.0
      y = -765.0
    }
    agent_options = jsonencode({"content_type": "json", "log_error_on_status": [], "method": "get", "url": "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"})
}

resource "tines_agent" "test_using_me_-_analyze_ip_2" {
    name = "TEST USING ME - Analyze IP"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = -315.0
      y = -900.0
    }
    agent_options = jsonencode({"payload": {"ipaddress": "218.74.39.3"}, "story": "{% story STS Analyze IP Address %}"})
}

resource "tines_agent" "webhook_agent_3" {
    name = "Webhook Agent"
    agent_type = "Agents::WebhookAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.lookup_ip_in_greynoise_8.id]
    position = {
      x = 105.0
      y = -1020.0
    }
    agent_options = jsonencode({"secret": "f48aa7ff977c9adc1b48979ebabffeb1", "verbs": "get,post"})
}

resource "tines_agent" "trigger_if_tor_node_4" {
    name = "Trigger if Tor Node"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.get_ip_address_reputation_details_in_talos_intelligence_5.id]
    position = {
      x = 105.0
      y = -705.0
    }
    agent_options = jsonencode({"emit_no_match": "true", "rules": [{"path": "{{.get_tor_nodes.body}}", "type": "regex", "value": "{{.webhook_agent.body.ipaddress}}"}]})
}

resource "tines_agent" "get_ip_address_reputation_details_in_talos_intelligence_5" {
    name = "Get IP Address Reputation Details in Talos Intelligence"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.search_for_ip_address_in_virustotal_6.id]
    position = {
      x = 105.0
      y = -630.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"Referer": "https://talosintelligence.com/reputation_center/lookup?search="}, "log_error_on_status": [], "method": "get", "payload": {"query": "/api/v2/details/ip/", "query_entry": "{{.webhook_agent.body.ipaddress}}"}, "url": "https://talosintelligence.com/sb_api/query_lookup"})
}

resource "tines_agent" "search_for_ip_address_in_virustotal_6" {
    name = "Search for IP Address in VirusTotal"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.check_ip_reputation_using_apivoid_0.id]
    position = {
      x = 105.0
      y = -525.0
    }
    agent_options = jsonencode({"headers": {"x-apikey": "{{.CREDENTIAL.virustotal}}"}, "method": "get", "payload": {}, "url": "https://www.virustotal.com/api/v3/ip_addresses/{{.webhook_agent.body.ipaddress}}"})
}

resource "tines_agent" "search_for_ip_address_in_abuse_ipdb_7" {
    name = "Search for IP Address in Abuse IPDB"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.search_issues_in_jira_10.id]
    position = {
      x = 105.0
      y = -345.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"key": "{% credential abuseipdb_bot %}"}, "log_error_on_status": [], "method": "get", "payload": {"ipAddress": "{{.webhook_agent.body.ipaddress}}", "maxAgeInDays": "90", "verbose": "true"}, "url": "https://api.abuseipdb.com/api/v2/check"})
}

resource "tines_agent" "lookup_ip_in_greynoise_8" {
    name = "Lookup IP in GreyNoise"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.lookup_ip_in_greynoise_riot_13.id]
    position = {
      x = 105.0
      y = -945.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"key": "{% credential greynoise %}"}, "log_error_on_status": [], "method": "get", "payload": {}, "url": "https://api.greynoise.io/v2/noise/context/{{.webhook_agent.body.ipaddress}}"})
}

resource "tines_agent" "build_results_9" {
    name = "Build Results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 105.0
      y = 15.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"TorNode": "{{.trigger_if_tor_node.rule_matched}}", "abuse_ipdb": "{{.search_for_ip_address_in_abuse_ipdb.body.data.abuseConfidenceScore}}", "apivoid_score": "{{.check_ip_reputation_using_apivoid.body.data.report.blacklists.detections}}", "greynoise": "{% if lookup_ip_in_greynoise.body.seen == true %}{{.lookup_ip_in_greynoise.body.classification}}{% else %}new{% endif %}", "ip": "{{.webhook_agent.body.ipaddress}}", "jira_results": "{{.search_issues_in_jira.body.issues | size }}", "location": "{{.check_ip_reputation_using_apivoid.body.data.report.information.city_name}}, {{.check_ip_reputation_using_apivoid.body.data.report.information.region_name}}, {{.check_ip_reputation_using_apivoid.body.data.report.information.country_name}}", "splunk_results": "{{.search_ip_in_splunk.results | size }}", "talos_email_score": "{{.get_ip_address_reputation_details_in_talos_intelligence.body.email_score_name}}", "virustotal_score": "{{.search_for_ip_address_in_virustotal.body.data.attributes.last_analysis_stats | as_object }}"}})
}

resource "tines_agent" "search_issues_in_jira_10" {
    name = "Search Issues in Jira"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.search_ip_in_splunk_11.id]
    position = {
      x = 105.0
      y = -255.0
    }
    agent_options = jsonencode({"basic_auth": "{% global_resource jira_svc_user %}:{% credential jira_svc_pwd %}", "content_type": "json", "method": "post", "payload": {"jql": "project=DEMO AND text ~ \"{{.webhook_agent.body.ipaddress}}\""}, "url": "https://{{ .RESOURCE.jira_domain }}/rest/api/2/search"})
}

resource "tines_agent" "search_ip_in_splunk_11" {
    name = "Search IP in Splunk"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.search_indicators_in_trustar_12.id]
    position = {
      x = 105.0
      y = -165.0
    }
    agent_options = jsonencode({"payload": {"search": "search source=proxy host=webproxy sourcetype=Bluecoat s_ip={{.webhook_agent.body.ipaddress}} | table s_ip _time c_ip cs_host cs_method cs_uri_path sc_status cs_Referer cs_User_Agent _raw"}, "send_payload_as_body": "false", "story": "{% story [Example] STS Search Splunk %}"})
}

resource "tines_agent" "search_indicators_in_trustar_12" {
    name = "Search Indicators in Trustar"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_9.id]
    position = {
      x = 105.0
      y = -90.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"Authorization": "Bearer {% credential trustar %}"}, "method": "post", "payload": [{"value": "{{.ioc}}"}], "url": "https://api.trustar.co/api/1.3/indicators/metadata"})
}

resource "tines_agent" "lookup_ip_in_greynoise_riot_13" {
    name = "Lookup IP in GreyNoise RIOT"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_analyze_ip_address.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.get_tor_nodes_1.id]
    position = {
      x = 105.0
      y = -855.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {"key": "{{ .CREDENTIAL.greynoise }}"}, "log_error_on_status": ["400-403", "405-500"], "method": "get", "payload": {}, "url": "https://api.greynoise.io/v2/riot/{{.webhook_agent.body.ipaddress }}"})
}
