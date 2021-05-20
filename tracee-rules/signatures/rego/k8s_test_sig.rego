package tracee.TRC_99

__rego_metadoc__ := {
    "id": "TRC-99",
    "version": "0.1.0",
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

tracee_match = res {
    g := input
    res := g
}
