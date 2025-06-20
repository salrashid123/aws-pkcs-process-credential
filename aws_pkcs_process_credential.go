package awspkcscredential

import (
	"context"
	"encoding/hex"
	"strconv"

	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	hmaccred "github.com/salrashid123/aws_hmac/pkcs"
	hmacsigner "github.com/salrashid123/aws_hmac/pkcs/signer"
	pkcs11uri "github.com/stefanberger/go-pkcs11uri"
)

const ()

// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
type ProcessCredentialsResponse struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

const (
	RFC3339 = "2006-01-02T15:04:05Z07:00"
)

type AWSPKCSConfig struct {
	PKCSURI        string
	AWSAccessKeyID string
	AWSRoleArn     string
	AWSRegion      string
	Duration       uint64
	AWSSessionName string
	AssumeRole     bool
}

var (
	cfg = AWSPKCSConfig{}
)

func NewAWSPKCSCredential(cfgValues *AWSPKCSConfig) (*ProcessCredentialsResponse, error) {

	cfg = *cfgValues

	if cfg.AWSAccessKeyID == "" || cfg.AWSRegion == "" || cfg.PKCSURI == "" {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: AWSAccessKeyID, AWSRegion and PKCSURI must be set")
	}

	uri := pkcs11uri.New()

	err := uri.Parse(cfg.PKCSURI)
	if err != nil {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: Error parsing pkcs11 URI %v\n", err)
	}

	//uri.SetAllowedModulePaths([]string{"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"})
	uri.SetAllowAnyModule(true)
	module, err := uri.GetModule()
	if err != nil {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: Error loading module from path %v\n", err)
	}

	pin, err := uri.GetPIN()
	if err != nil {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: Error extracting PIN from URI %v\n", err)
	}

	slot, ok := uri.GetPathAttribute("slot", false)
	if !ok {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: Error reading slot-id PIN from URI %s\n", cfg.PKCSURI)
	}
	slotid, err := strconv.Atoi(slot)
	if err != nil {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: Error converting slot to string %v\n", err)
	}

	id, ok := uri.GetPathAttribute("id", false)
	if !ok {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: Error loading PKCS ID from URI %s\n", cfg.PKCSURI)
	}

	hex_id, err := hex.DecodeString(id)
	if err != nil {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: Error converting hex id to string %v\n", err)
	}

	object, ok := uri.GetPathAttribute("object", false)
	if !ok {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: Error no object in URI %s\n", cfg.PKCSURI)
	}

	pkcsSigner, err := hmacsigner.NewPKCSSigner(&hmacsigner.PKCSSignerConfig{
		PKCSConfig: hmacsigner.PKCSConfig{
			Library: module,
			Slot:    slotid,
			Label:   object,
			PIN:     pin,
			Id:      hex_id,
		},
		AccessKeyID: cfg.AWSAccessKeyID,
	})
	if err != nil {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: creating signer open PKCS %s: %v", cfg.PKCSURI, err)
	}

	var creds *hmaccred.PKCSCredentialsProvider

	if cfg.AssumeRole {
		creds, err = hmaccred.NewAWSPKCSCredentials(hmaccred.PKCSProvider{
			AssumeRoleInput: &sts.AssumeRoleInput{
				RoleArn:         aws.String(cfg.AWSRoleArn),
				RoleSessionName: aws.String(cfg.AWSSessionName),
				DurationSeconds: aws.Int32(int32(cfg.Duration)),
			},
			Version:    "2011-06-15",
			Region:     cfg.AWSRegion,
			PKCSSigner: pkcsSigner,
		})
		if err != nil {

			return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: Could not initialize PKCS Credentials %v", err)
		}

	} else {

		creds, err = hmaccred.NewAWSPKCSCredentials(hmaccred.PKCSProvider{
			GetSessionTokenInput: &sts.GetSessionTokenInput{
				DurationSeconds: aws.Int32(int32(cfg.Duration)),
			},
			Version:    "2011-06-15",
			Region:     cfg.AWSRegion,
			PKCSSigner: pkcsSigner,
		})
		if err != nil {
			return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: Could not initialize PKCS Credentials %v", err)
		}
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(cfg.AWSRegion), config.WithCredentialsProvider(creds))
	if err != nil {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: Could not read GetCallerIdentity response %v", err)
	}

	val, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		return &ProcessCredentialsResponse{}, fmt.Errorf("aws-pkcs-process-credential: Error parsing STS Credentials %v", err)
	}

	return &ProcessCredentialsResponse{
		Version:         1,
		AccessKeyId:     val.AccessKeyID,
		SecretAccessKey: val.SecretAccessKey,
		SessionToken:    val.SessionToken,
		Expiration:      fmt.Sprintf("%s", val.Expires.Format(RFC3339)),
	}, nil

}
