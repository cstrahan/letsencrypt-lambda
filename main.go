package main

/*
TODO:
- Configuration
- Logging / better email
*/

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sns"
)

var (
	certExpiry           = 30 * 24 * time.Hour
	label_EC_PRIVATE_KEY = "EC PRIVATE KEY"
	label_CERTIFICATE    = "CERTIFICATE"
)

type Request struct {
	DirectoryUrl string   `json:"directoryUrl"`
	Contact      string   `json:"contact"`
	Domains      []string `json:"domains"`
	CloudFrontId string   `json:"cloudFrontId"`
	BucketName   string   `json:"bucketName"`
	SNSTopicARN  string   `json:"snsTopicArn"`
}

type Response struct{}

type fetcher struct {
	client *acme.Client
	acct   *acme.Account
	conf   Request

	contact string

	awsSession *session.Session
	cloudfront *cloudfront.CloudFront
	iam        *iam.IAM
	sns        *sns.SNS
	s3         *s3.S3

	snsTopicArn  string
	bucketname   string
	cloudfrontId string

	ctx context.Context
}

func main() {
	lambda.Start(Handler)
}

func newFetcher(ctx context.Context) (*fetcher, error) {
	region := "us-east-1"

	self := &fetcher{}
	self.ctx = ctx

	self.contact = "mailto:charles@cstrahan.com"

	self.awsSession = session.New(&aws.Config{Region: aws.String(region)})
	self.cloudfront = cloudfront.New(self.awsSession)
	self.iam = iam.New(self.awsSession)
	self.s3 = s3.New(self.awsSession)
	self.sns = sns.New(self.awsSession)

	self.snsTopicArn = "TODO"
	self.bucketname = "TODO"
	self.cloudfrontId = "TODO"

	// ACME init
	keyPEMptr, err := self.loadFile("letsencrypt", "acme-user.key")
	var key *ecdsa.PrivateKey
	if err != nil {
		return nil, err
	} else if key != nil {
		key, err = readKey([]byte(*keyPEMptr))
		if err != nil {
			return nil, err
		}
	} else {
		key, err = newKey()
		if err != nil {
			return nil, err
		}

		keyPEM, err := keyToPEM(key)
		if err != nil {
			return nil, err
		}

		err = self.saveFile("letsencrypt", "acme-user.key", string(keyPEM))
	}

	self.client = &acme.Client{
		Key: key,
		// "https://acme-v01.api.letsencrypt.org/directory",
		// "https://acme-staging.api.letsencrypt.org/directory",
		DirectoryURL: "https://acme-v01.api.letsencrypt.org/directory",
	}

	var acct *acme.Account
	acctJSONptr, err := self.loadFile("letsencrypt", "acme-user.json")
	if err != nil {
		return nil, err
	} else if acctJSONptr != nil {
		err = json.Unmarshal([]byte(*acctJSONptr), acct)
		if err != nil {
			return nil, err
		}

		acct, err = self.client.GetReg(self.ctx, acct.URI)
		if err != nil {
			return nil, err
		}

		if acct.AgreedTerms != acct.CurrentTerms {
			acct.AgreedTerms = acct.CurrentTerms
		}
	} else {
		acct = &acme.Account{Contact: []string{self.contact}}
	}

	// for now, we'll always update an existing account
	acct, err = self.client.Register(self.ctx, acct, acme.AcceptTOS)
	if err != nil {
		return nil, err
	}

	acctJSON, err := json.MarshalIndent(acct, "", "  ")
	if err != nil {
		return nil, err
	}

	err = self.saveFile("letsencrypt", "acme-user.json", string(acctJSON))
	if err != nil {
		return nil, err
	}

	self.acct = acct

	return self, nil
}

// lambda entry point
func Handler(ctx context.Context, request Request) (Response, error) {
	fetcher, err := newFetcher(ctx)
	if err != nil {
		return Response{}, err
	}

	err = fetcher.updateCert([]string{"cstrahan.com"})
	if err != nil {
		return Response{}, err
	}

	return Response{}, err
}

func (self *fetcher) updateCert(domains []string) error {
	certKey, err := newKey()
	if err != nil {
		return err
	}

	keypem, err := keyToPEM(certKey)
	if err != nil {
		return err
	}

	req := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domains[0]},
	}
	if len(domains) > 1 {
		req.DNSNames = domains
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, certKey)
	if err != nil {
		return err
	}

	for _, domain := range domains {
		ctx, cancel := context.Background(), func() {}
		defer cancel()
		err := self.authz(ctx, self.client, domain)
		if err != nil {
			return err
		}
	}

	// done with challenge, get cert.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	derCert, curl, err := self.client.CreateCert(ctx, csr, certExpiry, true /*bundle*/)
	_ = curl
	if err != nil {
		log.Fatalf("cert: %v", err)
	}

	// first block is our cert
	pemcert := pem.EncodeToMemory(&pem.Block{Type: label_CERTIFICATE, Bytes: derCert[0]})

	// subsequent blocks are the trust chain
	var pemchain []byte
	for _, b := range derCert[1:] {
		b = pem.EncodeToMemory(&pem.Block{Type: label_CERTIFICATE, Bytes: b})
		pemchain = append(pemchain, b...)
	}

	siteId := "cfd-" + self.cloudfrontId
	certname := siteId + "_" + time.Now().Format("20060102_150405")

	certId, certArn, err := self.iamUploadCert(certname, pemcert, keypem, pemchain)
	if err != nil {
		log.Printf("cert upload error: %v\n", err)
	}

	err = self.cloudfrontConfigureCert(self.cloudfrontId, certId, certArn)
	if err != nil {
		return err
	}

	return nil
}

func (self *fetcher) authz(ctx context.Context, client *acme.Client, domain string) error {
	z, err := self.client.Authorize(ctx, domain)
	if err != nil {
		return err
	}
	if z.Status == acme.StatusValid {
		return nil
	}
	var chal *acme.Challenge
	for _, c := range z.Challenges {
		//if c.Type == "dns-01" {
		if c.Type == "http-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return errors.New("no supported challenge found")
	}

	// respond to http-01 challenge
	self.solveS3Challenge(chal)
	if err != nil {
		return err
	}

	if _, err := self.client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept challenge: %v", err)
	}
	_, err = self.client.WaitAuthorization(ctx, z.URI)
	return err
}

// TODO: support dnsimple for dns-01 challenges

func (self *fetcher) iamUploadCert(certname string, pemcert []byte, pemkey []byte, pemchain []byte) (certid string, certarn string, err error) {
	newcert, err := self.iam.UploadServerCertificate(
		&iam.UploadServerCertificateInput{
			Path: aws.String("/cloudfront/"),
			ServerCertificateName: aws.String(string(certname)),
			CertificateBody:       aws.String(string(pemcert)),
			PrivateKey:            aws.String(string(pemkey)),
			CertificateChain:      aws.String(string(pemchain)),
		},
	)
	if err != nil {
		return "", "", err
	}

	// TODO: sanity check pointers
	certid = *newcert.ServerCertificateMetadata.ServerCertificateId
	certarn = *newcert.ServerCertificateMetadata.Arn
	return
}

func (self *fetcher) iamFindCertByArn(arn string) (*iam.ServerCertificateMetadata, error) {
	return self.iamFindCert(
		func(meta *iam.ServerCertificateMetadata) (bool, error) {
			return (meta.Arn != nil) && (*meta.Arn == arn), nil
		},
	)
}

func (self *fetcher) iamFindCertById(id string) (*iam.ServerCertificateMetadata, error) {
	return self.iamFindCert(
		func(meta *iam.ServerCertificateMetadata) (bool, error) {
			return (meta.ServerCertificateId != nil) && (*meta.ServerCertificateId == id), nil
		},
	)
}

func (self *fetcher) iamFindCert(pred func(*iam.ServerCertificateMetadata) (bool, error)) (*iam.ServerCertificateMetadata, error) {
	res, err := self.iam.ListServerCertificates(
		&iam.ListServerCertificatesInput{
			PathPrefix: aws.String("/cloudfront/"),
		},
	)
	if err != nil {
		return nil, err
	}

	for _, meta := range res.ServerCertificateMetadataList {
		res, err := pred(meta)
		if err != nil {
			return nil, err
		}

		if res {
			return meta, nil
		}
	}

	return nil, nil
}

func (self *fetcher) iamDeleteCert(certname string) {
	for retries := 5; retries > 0; retries -= 1 {
		_, err := self.iam.DeleteServerCertificate(
			&iam.DeleteServerCertificateInput{
				ServerCertificateName: aws.String(certname),
			},
		)
		if err == nil {
			// done
			return
		} else if isErr(err, iam.ErrCodeDeleteConflictException) {
			// might take a while for a cert to stop being in use
			time.Sleep(5 * time.Second)
		} else {
			log.Println("Unknown error occurred while deleting certificate '" + certname + "'")
			log.Println(err.Error())
			self.emailNotify(
				"Unable to delete certificate",
				"Failed to delete the certificate '"+certname+"'",
			)
			return
		}
	}

	log.Println("Could not delete certificate '" + certname + "'; still in use")
	self.emailNotify(
		"Unable to delete certificate",
		"Failed to delete the certificate '"+certname+"'",
	)
}

func (self *fetcher) cloudfrontConfigureCert(cloudfrontId string, certId string, certArn string) error {
	res, err := self.cloudfront.GetDistributionConfig(&cloudfront.GetDistributionConfigInput{Id: aws.String(cloudfrontId)})
	if err != nil {
		return err
	}

	cfg := res.DistributionConfig
	oldId := *cfg.ViewerCertificate.IAMCertificateId

	cfg.ViewerCertificate.CloudFrontDefaultCertificate = nil

	cfg.ViewerCertificate.IAMCertificateId = aws.String(certId)
	cfg.ViewerCertificate.Certificate = aws.String(certId)
	cfg.ViewerCertificate.CertificateSource = aws.String("iam")
	cfg.ViewerCertificate.MinimumProtocolVersion = aws.String("TLSv1")
	cfg.ViewerCertificate.SSLSupportMethod = aws.String("sni-only")

	self.cloudfront.UpdateDistribution(
		&cloudfront.UpdateDistributionInput{
			DistributionConfig: cfg,
			Id:                 aws.String(cloudfrontId),
			IfMatch:            res.ETag,
		},
	)
	if err != nil {
		return err
	}

	certMeta, err := self.iamFindCertById(oldId)
	if err != nil {
		return err
	} else if certMeta == nil {
		return errors.New("could not find cert with id '" + oldId + "'")
	}

	self.iamDeleteCert(*certMeta.ServerCertificateName)

	return nil
}

func (self *fetcher) solveS3Challenge(chal *acme.Challenge) error {
	tok, err := self.client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return err
	}

	body := bytes.NewReader([]byte(tok))
	expires := time.Now().Add(time.Hour * 24 * 3)
	_, err = self.s3.PutObject(&s3.PutObjectInput{Body: body, Expires: &expires})
	if err != nil {
		return err
	}

	return nil
}

func (self *fetcher) checkBucket(bucketname string) (bool, error) {
	_, err := self.s3.HeadBucket(&s3.HeadBucketInput{Bucket: aws.String(bucketname)})
	if isErr(err, s3.ErrCodeNoSuchBucket) {
		return false, nil
	}

	return false, err
}

func (self *fetcher) saveFile(directory string, filename string, content string) error {
	body := bytes.NewReader([]byte(content))

	_, err := self.s3.PutObject(
		&s3.PutObjectInput{
			Bucket: aws.String(self.bucketname),
			Key:    aws.String(directory + "/" + filename),
			Body:   body,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (self *fetcher) loadFile(directory string, filename string) (*string, error) {
	key := directory + "/" + filename

	obj, err := self.s3.GetObject(&s3.GetObjectInput{Bucket: aws.String(self.bucketname), Key: aws.String(key)})
	if isErr(err, s3.ErrCodeNoSuchKey) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(obj.Body)
	if err != nil {
		return nil, err
	}

	return aws.String(string(body)), nil
}

func (self *fetcher) emailNotify(subject string, message string) {
	res, err := self.sns.Publish(
		&sns.PublishInput{
			TopicArn: aws.String(self.snsTopicArn),
			Subject:  aws.String("[Lambda-LetsEncrypt] " + subject),
			Message:  aws.String(message),
		},
	)

	_, _ = res, err
	// TODO: log failure
}

func isErr(err error, awsErrType string) bool {
	if x := err.(awserr.Error); x != nil {
		return x.Code() == awsErrType
	}

	return false
}

// PEM encode the given key
func keyToPEM(k *ecdsa.PrivateKey) ([]byte, error) {
	bytes, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	b := &pem.Block{Type: label_EC_PRIVATE_KEY, Bytes: bytes}
	bytes = pem.EncodeToMemory(b)

	return bytes, nil
}

func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func readKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	decoded, _ := pem.Decode(keyPEM)
	if decoded == nil {
		return nil, errors.New("no block found in key material")
	}

	switch decoded.Type {
	case label_EC_PRIVATE_KEY:
		return x509.ParseECPrivateKey(decoded.Bytes)
	default:
		return nil, fmt.Errorf("%q is unsupported", decoded.Type)
	}
}
