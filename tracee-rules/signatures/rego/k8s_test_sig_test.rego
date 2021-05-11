package tracee.TRC_2

test_match_1 {
    tracee_match with input as {
       "honeypot_version": "2.0",
       "report_time": "2021-05-09T11:41:08.495443",
       "kind": "Event",
       "apiVersion": "audit.k8s.io/v1",
       "level": "Request",
       "auditID": "a364f6b6-d068-472e-896f-3e7a8bc55554",
       "stage": "ResponseComplete",
       "requestURI": "/manager/html",
       "verb": "get",
       "user": {
         "username": "minikube-user",
         "groups": [
           "system:masters",
           "system:authenticated"
         ]
       },
       "sourceIPs": [
         "195.154.62.232",
         "10.0.2.2",
         "10.0.2.15"
       ],
       "userAgent": "kubectl/v1.19.2 (linux/amd64) kubernetes/f574309",
       "responseStatus": {
         "metadata": {},
         "code": 404
       },
       "requestReceivedTimestamp": "2021-05-09T11:18:14.938167Z",
       "stageTimestamp": "2021-05-09T11:18:14.938596Z",
       "annotations": {
         "authorization.k8s.io/decision": "allow",
         "authorization.k8s.io/reason": ""
       },
       "attack_id": "20210509_1140"
     }
}
