### AWS Process Credentials for Hardware Security Module (HSM) with PKCS11

AWS [Process Credential](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) source where the `AWS_SECRET_ACCESS_KEY` is embedded into an HSM and accessed using `PKCS-11`

Use the binary as a way to use aws cli and any sdk library where after setup, you don't actually need to know the _source_ AWS_SECRET_ACCESS_KEY. 

To use this, you need to save the AWS_SECRET_ACCESS_KEY into an HSM:

1. Directly load `AWS_SECRET_ACCESS_KEY` 

   With this, you "load" the AWS_SECRET_ACCESS_KEY into a HSM and access the key though a PKCS URI 

2. Securely Transfer `AWS_SECRET_ACCESS_KEY` from one host to another


This repo shows how to do `1`

If you're curious how all this works, see

- [AWS Credentials for Hardware Security Modules and TPM based AWS_SECRET_ACCESS_KEY](https://github.com/salrashid123/aws_hmac)
- [PKCS 11 Samples in Go using SoftHSM](https://github.com/salrashid123/go_pkcs11)

>> note, this repo is **not** supported by google and is +experimental+

also see [AWS Process Credentials for Trusted Platform Module (TPM)](https://github.com/salrashid123/aws-tpm-process-credential)

---

### Quickstart (SoftHSM)

How you load an HMAC key into an HSM isn't covered here but what the following shows is how to demo this using  [SoftHSM](https://github.com/opendnssec/SoftHSMv2)

To use this,  [install go](https://go.dev/doc/install), `pkcs11-tool`, [SoftHSM](https://github.com/opendnssec/SoftHSMv2) and then run the following which load the key into the HSM

First export your 'original' AWS secrets

```bash
$ export AWS_ACCESS_KEY_ID=AKIAUH3H6EGK-redacted
$ export AWS_SECRET_ACCESS_KEY=--redacted--

## then seal it into softHSM (for example), follow https://github.com/salrashid123/aws_hmac/tree/main/example/pkcs

mkdir /tmp/tokens
wget https://raw.githubusercontent.com/salrashid123/aws_hmac/main/example/pkcs/softhsm/softhsm.conf
export SOFTHSM2_CONF=/path/to/softhsm.conf

## make sure softHSM library exists at /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so 
$ git clone https://github.com/salrashid123/aws_hmac.git
$ cd aws_hmac/example/pkcs

## if using softhsm,
### make sure SOFTHSM2_CONF is set and is pointing to the fully qualified path of softhsm.conf
$ go run create/main.go --hsmLibrary /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
     -accessKeyID $AWS_ACCESS_KEY_ID   -secretAccessKey $AWS_SECRET_ACCESS_KEY

## at this point your AWS key is loaded inside the HSM.
### to construct the URI, run

$ export PKCS_MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
$ pkcs11-tool --module $PKCS_MODULE --list-token-slots
Available slots:
Slot 0 (0x5f3a6d79): SoftHSM slot ID 0x5f3a6d79
  token label        : token1
  token manufacturer : SoftHSM project
  token model        : SoftHSM v2
  token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
  hardware version   : 2.6
  firmware version   : 2.6
  serial num         : e5cd05925f3a6d79
  pin min/max        : 4/255
Slot 1 (0x1): SoftHSM slot ID 0x1
  token state:   uninitialized

$ pkcs11-tool --module $PKCS_MODULE --list-objects  --pin mynewpin
Using slot 0 with a present token (0x5f3a6d79)
Secret Key Object; unknown key algorithm 43
  label:      HMACKey
  ID:         0100
  Usage:      verify
  Access:     sensitive
```


The PKCS URI for softHSM will use the serialnumber (`e5cd05925f3a6d79`), token (`token`), object (`HMACKey`), pin (`mynewpin`) and id (`0100`)
(your values will be different)

(please note this is **NOT** a comprehensive PKCS URI,  if you need modifications, please submit a PR)


In our case, the PKCS URI looks like..so go back to the root of this repo and test the standalone request

```bash
export PKCS11_URI="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;slot=0;serial=e5cd05925f3a6d79;token=token1;object=HMACKey;id=0100?pin-value=mynewpin&module-path=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"

export AWS_ACCESS_KEY_ID=AKIAUH3H6EGK-redacted

## if using softhsm:
# export SOFTHSM2_CONF=/full/path/to/softhsm.conf

# test standalone credentials
go run load/main.go --pkcs-uri=$PKCS11_URI --aws-access-key-id=$AWS_ACCESS_KEY_ID --aws-region=us-east-1
```

### Configure AWS Process Credential Profiles

To test the process credential API and persistent handle, first download `aws-pkcs-process-credential` from the Releases section or build it on your own

This repo will assume a role  `"arn:aws:iam::291738886548:user/svcacct1"` has access to AssumeRole on `arn:aws:iam::291738886548:role/gcpsts` and both the user and role has access to an s3 bucket

![images/role_trust.png](images/role_trust.png)


Edit  `~/.aws/config` and set the process credential parameters 

```conf
[profile sessiontoken]
credential_process = /path/to/aws-pkcs-process-credential  --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=false  --pkcs-uri="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;slot=0;serial=e5cd05925f3a6d79;token=token1;object=HMACKey;id=0100?pin-value=mynewpin&module-path=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" --aws-access-key-id=AKIAUH3H6EGK-redacted  --duration=3600

[profile assumerole]
credential_process = /path/to/aws-pkcs-process-credential  --aws-arn="arn:aws:iam::291738886548:role/gcpsts" --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=true  --pkcs-uri="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;slot=0;serial=e5cd05925f3a6d79;token=token1;object=HMACKey;id=0100?pin-value=mynewpin&module-path=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" --aws-access-key-id=AKIAUH3H6EGK-redacted  --duration=3600 
```

#### Verify AssumeRole


To verify `AssumeRole` first just run `aws-tpm-process-credential` directly

```bash
$ /path/to/aws-pkcs-process-credential  --pkcs-uri=$PKCS11_URI \
   --aws-arn="arn:aws:iam::291738886548:role/gcpsts" --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=true  --aws-access-key-id=$AWS_ACCESS_KEY_ID  --duration=3600 

{
  "Version": 1,
  "AccessKeyId": "ASIAUH3H6EGKIA6WLCJG",
  "SecretAccessKey": "h7anawgBS5xNPlUcJ2P7x9YED5iltredacted",
  "SessionToken": "FwoGZXIvYXdzEKz//////////wEaDK+OR7VuQewac2+redacted",
  "Expiration": "2023-10-29T19:33:27+0000"
}
```

if that works, verify the aws cli

```bash
$ aws sts get-caller-identity  --profile assumerole
{
    "UserId": "AROAUH3H6EGKHZUSB4BC5:mysession",
    "Account": "291738886548",
    "Arn": "arn:aws:sts::291738886548:assumed-role/gcpsts/mysession"
}

# then finally s3
$  aws s3 ls mineral-minutia --region us-east-2 --profile sessiontoken
2020-08-10 02:52:08        411 README.md
2020-11-03 00:16:00          3 foo.txt
```

#### Verify SessionToken

To verify the session token, first just run `aws-tpm-process-credential` directly

```bash
$  /path/to/aws-pkcs-process-credential  --pkcs-uri=$PKCS11_URI \
    --aws-region=us-east-1 --aws-session-name=mysession --assumeRole=false --aws-access-key-id=$AWS_ACCESS_KEY_ID  --duration=3600

{
  "Version": 1,
  "AccessKeyId": "ASIAUH3H6EGKFOX7G5XU",
  "SecretAccessKey": "lwfjGGh41y/3RI0HUlYJFCK5LWxredacted",
  "SessionToken": "FwoGZXIvYXdzEKv//////////wEaDOrG0ZqGoVCnU89juyKBredacted",
  "Expiration": "2023-10-29T18:59:58+0000"
}
```

if that works, verify the aws cli

```bash
$ aws sts get-caller-identity  --profile sessiontoken
{
    "UserId": "AIDAUH3H6EGKDO36JYJH3",
    "Account": "291738886548",
    "Arn": "arn:aws:iam::291738886548:user/svcacct1"
}

# then finally s3
$ aws s3 ls mineral-minutia --region us-east-2 --profile sessiontoken
2020-08-10 02:52:08        411 README.md
2020-11-03 00:16:00          3 foo.txt
```


### Testing

```bash
export AWS_ACCESS_KEY_ID=redacted
export AWS_SECRET_ACCESS_KEY=redacted
export AWS_ROLE_SESSION_NAME=mysession
export AWS_DEFAULT_REGION=us-east-1
export AWS_ROLE_ARN=arn:aws:iam::291738886548:role/cicdrole
export AWS_ACCOUNT_ARN=arn:aws:iam::291738886548:user/testservice
export AWS_ROLE_SESSION_ARN=arn:aws:sts::291738886548:assumed-role/cicdrole/mysession

go test -v
```

---

#### References

- [TPM Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-tpm)
- [PKCS-11 Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-pkcs)
- [AWS Authentication using TPM HMAC](https://github.com/salrashid123/aws_hmac/tree/main/example/tpm#usage-tpm)
- [AWS Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

