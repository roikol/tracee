package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type k8sApiEvent struct {
	HoneypotVersion          string `json:"honeypot_version"`
	ReportTime               string `json:"report_time"`
	Kind                     string `json:"kind"`
	ApiVersion               string `json:"apiVersion"`
	Level                    string `json:"level"`
	AuditID                  string `json:"auditID"`
	Stage                    string `json:"stage"`
	RequestURI               string `json:"requestURI"`
	Verb                     string `json:"verb"`
	User                     k8sUser
	SourceIPs                []string `json:"sourceIPs"`
	UserAgent                string   `json:"userAgent"`
	ResponseStatus           k8sResponseStatus
	RequestReceivedTimestamp string `json:"requestReceivedTimestamp"`
	StageTimestamp           string `json:"stageTimestamp"`
	Annotations              k8sAnnotations
	AttackId                 string `json:"attack_id"`
}

type k8sUser struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type k8sResponseStatus struct {
	Metadata map[string]interface{} `json:"metadata"`
	Code     int                    `json:"code"`
}

type k8sAnnotations struct {
	AuthorisationDecision string `json:"authorization.k8s.io/decision"`
	AuthorisationReason   string `json:"authorization.k8s.io/reason"`
}

type k8sApiInputOptions struct {
	inputFile   *os.File
	inputFormat inputFormat
}

func setupK8sApiInputSource(opts *k8sApiInputOptions) (chan types.Event, error) {

	if opts.inputFormat == jsonInputFormat {
		return setupK8sApiJSONInputSource(opts)
	}

	return nil, errors.New("could not set up input source")
}

func setupK8sApiJSONInputSource(opts *k8sApiInputOptions) (chan types.Event, error) {
	res := make(chan types.Event)
	scanner := bufio.NewScanner(opts.inputFile)
	go func() {
		for scanner.Scan() {
			event := scanner.Bytes()
			var e k8sApiEvent
			err := json.Unmarshal(event, &e)
			if err != nil {
				log.Printf("invalid json in %s: %v", string(event), err)
			}
			res <- e
		}
		opts.inputFile.Close()
		close(res)
	}()
	return res, nil
}

func parseK8sApiInputOptions(inputOptions []string) (*k8sApiInputOptions, error) {

	var (
		inputSourceOptions k8sApiInputOptions
		err                error
	)

	if len(inputOptions) == 0 {
		return nil, errors.New("no k8s-api input options specified")
	}

	for i := range inputOptions {
		if inputOptions[i] == "help" {
			return nil, errHelp
		}

		kv := strings.Split(inputOptions[i], ":")
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid input-k8s-api option: %s", inputOptions[i])
		}
		if kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("empty key or value passed: key: >%s< value: >%s<", kv[0], kv[1])
		}
		if kv[0] == "file" {
			err = parseK8sApiInputFile(&inputSourceOptions, kv[1])
			if err != nil {
				return nil, err
			}
		} else if kv[0] == "format" {
			err = parseK8sApiInputFormat(&inputSourceOptions, kv[1])
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("invalid input-k8s-api option key: %s", kv[0])
		}
	}
	return &inputSourceOptions, nil
}

func parseK8sApiInputFile(option *k8sApiInputOptions, fileOpt string) error {

	if fileOpt == "stdin" {
		option.inputFile = os.Stdin
		return nil
	}
	_, err := os.Stat(fileOpt)
	if err != nil {
		return fmt.Errorf("invalid Tracee input file: %s", fileOpt)
	}
	f, err := os.Open(fileOpt)
	if err != nil {
		return fmt.Errorf("invalid file: %s", fileOpt)
	}
	option.inputFile = f
	return nil
}

func parseK8sApiInputFormat(option *k8sApiInputOptions, formatString string) error {
	formatString = strings.ToUpper(formatString)

	if formatString == "JSON" {
		option.inputFormat = jsonInputFormat
	} else {
		option.inputFormat = invalidInputFormat
		return fmt.Errorf("invalid tracee input format specified: %s", formatString)
	}
	return nil
}

func printK8sHelp() {
	k8sApiInputHelp := `
tracee-rules --input-ks8-api <key:value>,<key:value> --input-ks8-api <key:value>

you should supply an output-template, so tracee-rules would know how to print a detection:
"
*** Detection ***
Time: {{ dateInZone "2006-01-02T15:04:05Z" (now) "UTC" }}
Signature ID: {{ .SigMetadata.ID }}
Signature: {{ .SigMetadata.Name }}
Data: {{ .Data }}
RequestURI: {{ .Context.RequestURI }}
User: {{ .Context.User.Username }}
"

Specify various key value pairs for input options k8s-api. The following key options are available:

'file'   - Input file source. You can specify a relative or absolute path. You may also specify 'stdin' for standard input.
'format' - Input format. Options currently include only 'JSON'.

Examples:

'cat k8s_event.json | tracee-rules --input-ks8-api file:stdin --input-ks8-api format:json --output-template=k8s_event_template.tmpl'
`

	fmt.Println(k8sApiInputHelp)
}
