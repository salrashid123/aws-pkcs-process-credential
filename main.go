package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"flag"

	"github.com/google/uuid"

	hmaccred "github.com/salrashid123/aws_hmac/pkcs"
	hmacsigner "github.com/salrashid123/aws_hmac/pkcs/signer"
	pkcs11uri "github.com/stefanberger/go-pkcs11uri"
)

const ()

// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
type processCredentialsResponse struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

const (
	RFC3339 = "2006-01-02T15:04:05Z07:00"
)

type credConfig struct {
	flPKCSURI        string
	flAWSAccessKeyID string
	flAWSRoleArn     string
	flAWSRegion      string
	flDuration       uint64
	flAWSSessionName string
	flAssumeRole     bool
}

var (
	cfg = &credConfig{}
)

func main() {

	flag.StringVar(&cfg.flPKCSURI, "pkcs-uri", "", "FULL PKCS URI")
	flag.Uint64Var(&cfg.flDuration, "duration", uint64(3600), "Duration value")
	flag.StringVar(&cfg.flAWSRoleArn, "aws-arn", "", "AWS ARN Value")
	flag.StringVar(&cfg.flAWSRegion, "aws-region", "", "AWS Region")
	flag.BoolVar(&cfg.flAssumeRole, "assumeRole", false, "Assume Role")
	flag.StringVar(&cfg.flAWSAccessKeyID, "aws-access-key-id", "", "(required) AWS access key id")
	flag.StringVar(&cfg.flAWSSessionName, "aws-session-name", fmt.Sprintf("gcp-%s", uuid.New().String()), "AWS SessionName")

	flag.Parse()

	argError := func(s string, v ...interface{}) {
		//flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "Invalid Argument error: "+s, v...)
		os.Exit(1)
	}

	if cfg.flAWSAccessKeyID == "" || cfg.flAWSRegion == "" || cfg.flPKCSURI == "" {
		argError("-aws-access-key-id --aws-region cannot be null")
	}

	uri := pkcs11uri.New()

	err := uri.Parse(cfg.flPKCSURI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-pkcs-process-credential: Error parsing pkcs11 URI %v\n", err)
		os.Exit(1)
	}

	//uri.SetAllowedModulePaths([]string{"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"})
	uri.SetAllowAnyModule(true)
	module, err := uri.GetModule()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-pkcs-process-credential: Error loading module from path %v\n", err)
		os.Exit(1)
	}

	pin, err := uri.GetPIN()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-pkcs-process-credential: Error extracting PIN from URI %v\n", err)
		os.Exit(1)
	}

	slot, ok := uri.GetPathAttribute("slot", false)
	if !ok {
		fmt.Fprintf(os.Stderr, "aws-pkcs-process-credential: Error reading slot-id PIN from URI %s\n", cfg.flPKCSURI)
		os.Exit(1)
	}
	slotid, err := strconv.Atoi(slot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-pkcs-process-credential: Error converting slot to string %v\n", err)
		os.Exit(1)
	}

	id, ok := uri.GetPathAttribute("id", false)
	if !ok {
		fmt.Fprintf(os.Stderr, "aws-pkcs-process-credential: Error loading PKCS ID from URI %s\n", cfg.flPKCSURI)
		os.Exit(1)
	}

	hex_id, err := hex.DecodeString(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-pkcs-process-credential: Error converting hex id to string %v\n", err)
		os.Exit(1)
	}

	object, ok := uri.GetPathAttribute("object", false)
	if !ok {
		fmt.Fprintf(os.Stderr, "aws-pkcs-process-credential: Error no object in URI %s\n", cfg.flPKCSURI)
		os.Exit(1)
	}

	pkcsSigner, err := hmacsigner.NewPKCSSigner(&hmacsigner.PKCSSignerConfig{
		PKCSConfig: hmacsigner.PKCSConfig{
			Library: module,
			Slot:    slotid,
			Label:   object,
			PIN:     pin,
			Id:      hex_id,
		},
		AccessKeyID: cfg.flAWSAccessKeyID,
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating signer open PKCS %s: %v", cfg.flPKCSURI, err)
		os.Exit(1)
	}

	var creds *hmaccred.PKCSCredentialsProvider

	if cfg.flAssumeRole {
		creds, err = hmaccred.NewAWSPKCSCredentials(hmaccred.PKCSProvider{
			AssumeRoleInput: &sts.AssumeRoleInput{
				RoleArn:         aws.String(cfg.flAWSRoleArn),
				RoleSessionName: aws.String(cfg.flAWSSessionName),
				DurationSeconds: aws.Int32(int32(cfg.flDuration)),
			},
			Version:    "2011-06-15",
			Region:     cfg.flAWSRegion,
			PKCSSigner: pkcsSigner,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not initialize PKCS Credentials %v", err)
			os.Exit(1)
		}

	} else {

		creds, err = hmaccred.NewAWSPKCSCredentials(hmaccred.PKCSProvider{
			GetSessionTokenInput: &sts.GetSessionTokenInput{
				DurationSeconds: aws.Int32(int32(cfg.flDuration)),
			},
			Version:    "2011-06-15",
			Region:     cfg.flAWSRegion,
			PKCSSigner: pkcsSigner,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not initialize PKCS Credentials %v", err)
			os.Exit(1)
		}
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(cfg.flAWSRegion), config.WithCredentialsProvider(creds))
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v", err)
		return
	}

	val, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing STS Credentials %v", err)
		os.Exit(1)
	}

	resp := &processCredentialsResponse{
		Version:         1,
		AccessKeyId:     val.AccessKeyID,
		SecretAccessKey: val.SecretAccessKey,
		SessionToken:    val.SessionToken,
		Expiration:      fmt.Sprintf("%s", val.Expires.Format(RFC3339)),
	}

	m, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling processCredential output %v", err)
		os.Exit(1)
	}
	fmt.Println(string(m))
}
