package awspkcscredential

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	newpin       = "mynewpin"
	defaultpin   = "1234"
	defaultLabel = "token1"
)

var (
	//lib = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
	lib = "/usr/lib/softhsm/libsofthsm2.so"
)

func loadKey(t *testing.T, awsSecret string) ([]byte, string, error) {

	tempDir := t.TempDir()
	tempFilePath := filepath.Join(tempDir, "softhsm.conf")

	softHSMConf := fmt.Sprintf(`\nlog.level = DEBUG
objectstore.backend = file
directories.tokendir = %s
slots.removable = true`, tempDir)

	// Write the content to the temporary file
	err := os.WriteFile(tempFilePath, []byte(softHSMConf), 0644)
	if err != nil {
		return nil, "", err
	}

	t.Setenv("SOFTHSM2_CONF", tempFilePath)

	p := pkcs11.New(lib)

	err = p.Initialize()
	if err != nil {
		return nil, "", err
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, "", err
	}

	err = p.InitToken(0, defaultpin, defaultLabel)
	if err != nil {
		return nil, "", err
	}

	ssession, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, "", err
	}
	defer p.CloseSession(ssession)

	err = p.Login(ssession, pkcs11.CKU_SO, defaultpin)
	if err != nil {
		return nil, "", err
	}

	err = p.InitPIN(ssession, newpin)
	if err != nil {
		return nil, "", err
	}

	err = p.Logout(ssession)
	if err != nil {
		return nil, "", err
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, "", err
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, newpin)
	if err != nil {
		return nil, "", err
	}
	defer p.Logout(session)

	// info, err := p.GetInfo()
	// if err != nil {
	// 	return nil, err
	// }
	//t.Logf("CryptokiVersion.Major %v", info.CryptokiVersion.Major)

	c, err := p.GetTokenInfo(0)
	if err != nil {
		return nil, "", err
	}
	//t.Logf("SerialNumber %s", c.SerialNumber)

	// first lookup the key
	buf := new(bytes.Buffer)
	var num uint16 = 1
	err = binary.Write(buf, binary.LittleEndian, num)
	require.NoError(t, err)
	id := buf.Bytes()

	hmacKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_SHA256_HMAC),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), // we do need to extract this
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte(awsSecret)), // make([]byte, 32)), /* KeyLength */
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "HMACKey"),         /* Name of Key */
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	_, err = p.CreateObject(session, hmacKeyTemplate)
	if err != nil {
		return nil, "", err
	}
	return id, c.SerialNumber, nil
}

func TestToken(t *testing.T) {

	awsKey := os.Getenv("AWS_ACCESS_KEY_ID")
	testAccountArn := os.Getenv("AWS_ACCOUNT_ARN")
	awsRegion := os.Getenv("AWS_DEFAULT_REGION")
	awsSecret := os.Getenv("AWS_SECRET_ACCESS_KEY")

	id, serial, err := loadKey(t, fmt.Sprintf("AWS4%s", awsSecret))
	require.NoError(t, err)

	pkcsURI := fmt.Sprintf("pkcs11:model=SoftHSM%%20v2;manufacturer=SoftHSM%%20project;slot=0;serial=%s;token=token1;object=HMACKey;id=%s?pin-value=mynewpin&module-path=%s", serial, hex.EncodeToString(id), lib)

	resp, err := NewAWSPKCSCredential(&AWSPKCSConfig{
		PKCSURI:        pkcsURI,
		AWSAccessKeyID: awsKey,
		AWSRegion:      awsRegion,
		Duration:       900,
		AssumeRole:     false,
	})
	require.NoError(t, err)

	t.Setenv("AWS_ACCESS_KEY_ID", resp.AccessKeyId)
	t.Setenv("AWS_SECRET_ACCESS_KEY", resp.SecretAccessKey)
	t.Setenv("AWS_SESSION_TOKEN", resp.SessionToken)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	require.NoError(t, err)

	stssvc := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.Region = awsRegion
	})

	stsresp, err := stssvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	require.NoError(t, err)

	require.Equal(t, testAccountArn, aws.ToString(stsresp.Arn))

}

func TestTokenAssumeRole(t *testing.T) {

	awsKey := os.Getenv("AWS_ACCESS_KEY_ID")
	testAccountArn := os.Getenv("AWS_ROLE_SESSION_ARN")
	awsRegion := os.Getenv("AWS_DEFAULT_REGION")
	awsSessionName := os.Getenv("AWS_ROLE_SESSION_NAME")
	awsRoleARN := os.Getenv("AWS_ROLE_ARN")
	awsSecret := os.Getenv("AWS_SECRET_ACCESS_KEY")

	id, serial, err := loadKey(t, fmt.Sprintf("AWS4%s", awsSecret))
	require.NoError(t, err)

	pkcsURI := fmt.Sprintf("pkcs11:model=SoftHSM%%20v2;manufacturer=SoftHSM%%20project;slot=0;serial=%s;token=token1;object=HMACKey;id=%s?pin-value=mynewpin&module-path=%s", serial, hex.EncodeToString(id), lib)

	resp, err := NewAWSPKCSCredential(&AWSPKCSConfig{
		PKCSURI:        pkcsURI,
		AWSAccessKeyID: awsKey,
		AWSRoleArn:     awsRoleARN,
		AWSRegion:      awsRegion,
		Duration:       900,
		AWSSessionName: awsSessionName,
		AssumeRole:     true,
	})
	require.NoError(t, err)

	t.Setenv("AWS_ACCESS_KEY_ID", resp.AccessKeyId)
	t.Setenv("AWS_SECRET_ACCESS_KEY", resp.SecretAccessKey)
	t.Setenv("AWS_SESSION_TOKEN", resp.SessionToken)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	require.NoError(t, err)

	stssvc := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.Region = awsRegion
	})

	stsresp, err := stssvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	require.NoError(t, err)

	require.Equal(t, testAccountArn, aws.ToString(stsresp.Arn))

}
