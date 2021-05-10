package main

__rego_metadoc__ := {
    "name": "k8s-test",
    "description": "k8s-test",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 3,
        "MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
    }
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "k8s",
		"name": ""
	}
}

tracee_match {
    input["kind"] == "Event"
}
