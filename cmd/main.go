package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/uuid"
	awspkcscredential "github.com/salrashid123/aws-pkcs-process-credential"
)

const ()

var (
	pkcsURI        = flag.String("pkcs-uri", "", "FULL PKCS URI")
	duration       = flag.Uint64("duration", uint64(3600), "Duration value")
	awsRoleArn     = flag.String("aws-arn", "", "AWS ARN Value")
	awsRegion      = flag.String("aws-region", "", "AWS Region")
	assumeRole     = flag.Bool("assumeRole", false, "Assume Role")
	awsAccessKeyID = flag.String("aws-access-key-id", "", "(required) AWS access key id")
	awsSessionName = flag.String("aws-session-name", fmt.Sprintf("gcp-%s", uuid.New().String()), "AWS SessionName")
	version        = flag.Bool("version", false, "print version")

	Commit, Tag, Date string
)

func main() {

	flag.Parse()

	if *version {
		// go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
		fmt.Printf("Version: %s\n", Tag)
		fmt.Printf("Date: %s\n", Date)
		fmt.Printf("Commit: %s\n", Commit)
		os.Exit(0)
	}

	resp, err := awspkcscredential.NewAWSPKCSCredential(&awspkcscredential.AWSPKCSConfig{
		PKCSURI:        *pkcsURI,
		AWSAccessKeyID: *awsAccessKeyID,
		AWSRoleArn:     *awsRoleArn,
		AWSRegion:      *awsRegion,
		Duration:       *duration,
		AWSSessionName: *awsSessionName,
		AssumeRole:     *assumeRole,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-pkcs-process-credential: Error getting credentials %v", err)
		os.Exit(1)
	}
	m, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-pkcs-process-credential: Error marshalling processCredential output %v", err)
		os.Exit(1)
	}
	fmt.Println(string(m))
}
