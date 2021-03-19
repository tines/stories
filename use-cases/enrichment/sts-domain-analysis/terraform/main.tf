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

resource "tines_story" "sts_domain_analysis" {
    name = "StS Domain Analysis"
    team_id = var.team_id
    description = <<EOF

EOF
}


resource "tines_agent" "build_results_0" {
    name = "build results"
    agent_type = "Agents::EventTransformationAgent"
    story_id = tines_story.sts_domain_analysis.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 225.0
      y = -195.0
    }
    agent_options = jsonencode({"mode": "message_only", "payload": {"alexa_top_10k": "{{.check_apivoid_for_domain.body.data.report.alexa_top_10k}}", "apivoid": "{% if .check_apivoid_for_domain.body.data.report.blacklists.detections == 0 %}New{% else %}Malicious{% endif %}", "domain": "{{.receive_events.domain}}", "domain_age": "{% if .get_domain_age.body.error %}{{.get_domain_age.body.error}}{% else %}{{.get_domain_age.body.data.domain_age_in_days}}{% endif %}", "forcepoint_category": "{% if .search_domain_in_virustotal.body[\u0027Forcepoint ThreatSeeker category\u0027] %}{{.search_domain_in_virustotal.body[\u0027Forcepoint ThreatSeeker category\u0027]}}{% else %}unknown{% endif %}", "gsb": "{% assign gsb_results = search_domain_in_gsb.body.matches | join: \" \" %}{% if gsb_results contains \"social_engineering\" %}Social Engineering{% elsif gsb_results contains \"MALWARE\" %}Malware{% else %}Clean{% endif %}", "raw": "{{.check_apivoid_for_domain | as_object }}", "urlscan": "{% if .search_domains_in_urlscan_io.body.total == 0 %}New{% elsif .view_domain_results_in_urlscan.body.task.source contains \"certstream-suspicious\" %}Malicious {% else %}Clean{% endif %}"}})
}

resource "tines_agent" "search_domain_in_gsb_1" {
    name = "Search Domain in GSB"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_domain_analysis.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.search_domain_in_virustotal_5.id]
    position = {
      x = 225.0
      y = -840.0
    }
    agent_options = jsonencode({"content_type": "json", "headers": {}, "log_error_on_status": [], "method": "post", "payload": {"client": {"clientId": "tinessecurityservices", "clientVersion": "1.0.0"}, "threatInfo": {"platformTypes": ["PLATFORM_TYPE_UNSPECIFIED", "WINDOWS", "LINUX", "ANDROID", "OSX", "IOS", "ANY_PLATFORM", "ALL_PLATFORMS", "CHROME"], "threatEntries": [{"url": "http://{{.receive_events.domain}}"}], "threatEntryTypes": ["URL"], "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "THREAT_TYPE_UNSPECIFIED", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]}}, "url": "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={% credential GSB %}"})
}

resource "tines_agent" "trigger_if_no_urlscan_results_2" {
    name = "trigger if no urlscan results"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.sts_domain_analysis.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.check_apivoid_for_domain_6.id]
    position = {
      x = 345.0
      y = -555.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .search_domains_in_urlscan_io.body.total }}", "type": "field==value", "value": "0"}]})
}

resource "tines_agent" "view_domain_results_in_urlscan_3" {
    name = "view domain results in urlscan"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_domain_analysis.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.check_apivoid_for_domain_6.id]
    position = {
      x = 105.0
      y = -465.0
    }
    agent_options = jsonencode({"content_type": "json", "fail_on_status": "true", "headers": {"API-Key": "{% credential urlscan_io %}"}, "log_error_on_status": [], "method": "get", "url": "https://urlscan.io/api/v1/result/{{.search_domains_in_urlscan_io.body.results.first._id}}"})
}

resource "tines_agent" "trigger_if_urlscan_results_exist_4" {
    name = "trigger if urlscan results exist"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.sts_domain_analysis.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.view_domain_results_in_urlscan_3.id]
    position = {
      x = 105.0
      y = -555.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .search_domains_in_urlscan_io.body.total }}", "type": "field\u003evalue", "value": "0"}]})
}

resource "tines_agent" "search_domain_in_virustotal_5" {
    name = "search domain in Virustotal"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_domain_analysis.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.search_domains_in_urlscan.io_8.id]
    position = {
      x = 225.0
      y = -765.0
    }
    agent_options = jsonencode({"fail_on_status": "true", "log_error_on_status": [], "method": "get", "payload": {"apikey": "{% credential virustotal %}", "domain": "{{.receive_events.domain}}"}, "url": "https://www.virustotal.com/vtapi/v2/domain/report"})
}

resource "tines_agent" "check_apivoid_for_domain_6" {
    name = "Check APIVoid for Domain"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_domain_analysis.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.get_domain_age_9.id]
    position = {
      x = 225.0
      y = -360.0
    }
    agent_options = jsonencode({"content_type": "json", "fail_on_status": "true", "log_error_on_status": [], "method": "get", "payload": {"host": "{{.receive_events.domain}}", "key": "{% credential apivoid %}"}, "url": "https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/"})
}

resource "tines_agent" "sts_analyze_domain_7" {
    name = "STS Analyze Domain"
    agent_type = "Agents::SendToStoryAgent"
    story_id = tines_story.sts_domain_analysis.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = []
    position = {
      x = 570.0
      y = -915.0
    }
    agent_options = jsonencode({"payload": {"action": "inveestigate/network", "domain": "irishtimes.com"}, "send_payload_as_body": "false", "story": "{% story StS Domain Analysis %}"})
}

resource "tines_agent" "search_domains_in_urlscan.io_8" {
    name = "search domains in urlscan.io"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_domain_analysis.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_no_urlscan_results_2.id, tines_agent.trigger_if_urlscan_results_exist_4.id]
    position = {
      x = 225.0
      y = -675.0
    }
    agent_options = jsonencode({"content_type": "json", "fail_on_status": "true", "headers": {"API-Key": "{% credential urlscan_io %}"}, "log_error_on_status": [], "method": "get", "url": "https://urlscan.io/api/v1/search/?q=domain:{{.receive_events.domain}}"})
}

resource "tines_agent" "get_domain_age_9" {
    name = "Get Domain Age"
    agent_type = "Agents::HTTPRequestAgent"
    story_id = tines_story.sts_domain_analysis.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.build_results_0.id]
    position = {
      x = 225.0
      y = -270.0
    }
    agent_options = jsonencode({"content_type": "json", "log_error_on_status": [], "method": "get", "payload": {"host": "{{.receive_events.domain}}", "key": "{% credential apivoid %}"}, "url": "https://endpoint.apivoid.com/domainage/v1/pay-as-you-go/"})
}

resource "tines_agent" "receive_events_10" {
    name = "receive events"
    agent_type = "Agents::WebhookAgent"
    story_id = tines_story.sts_domain_analysis.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.trigger_if_known_good_11.id]
    position = {
      x = 225.0
      y = -975.0
    }
    agent_options = jsonencode({"include_headers": "false", "secret": "40ec25bf6ddf6eb6c911b2526c89c9cb", "verbs": "get,post"})
}

resource "tines_agent" "trigger_if_known_good_11" {
    name = "Trigger if Known Good"
    agent_type = "Agents::TriggerAgent"
    story_id = tines_story.sts_domain_analysis.id
    keep_events_for = 0
    source_ids = []
    receiver_ids = [tines_agent.search_domain_in_gsb_1.id]
    position = {
      x = 225.0
      y = -915.0
    }
    agent_options = jsonencode({"rules": [{"path": "{{ .somekey.subkey.subkey.goal }}", "type": "regex", "value": "foo\\d+bar"}]})
}
