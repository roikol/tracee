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
			validJson := json.Valid(event)
			if !validJson {
				log.Printf("invalid json in %s", string(event))
			}
			fmt.Printf("json event is valid.\n")
			res <- event
			fmt.Printf("sent event to channel res.\n")
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
tracee-rules --input-ks8-api <key:value>,<key:value> --input-tracee <key:value>

Specify various key value pairs for input options tracee-ebpf. The following key options are available:

'file'   - Input file source. You can specify a relative or absolute path. You may also specify 'stdin' for standard input.
'format' - Input format. Options currently include 'JSON' and 'GOB'. Both can be specified as output formats from tracee-ebpf.

Examples:

'tracee-rules --input-tracee file:./events.json --input-tracee format:json'
'tracee-rules --input-tracee file:./events.gob --input-tracee format:gob'
'sudo tracee-ebpf -o format:gob | tracee-rules --input-tracee file:stdin --input-tracee format:gob'
`

	fmt.Println(k8sApiInputHelp)
}
