package main

/*
TODO:
- Configuration
- Logging / better email
*/

// https://www.alexedwards.net/blog/serverless-api-with-go-and-aws-lambda#creating-and-deploying-an-lambda-function

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

const (
	USER_ACCOUNT_FILE = "acme-user.json"
	USER_KEY_FILE     = "acme-user.key"

	certExpiry            = 30 * 24 * time.Hour
	label_EC_PRIVATE_KEY  = "EC PRIVATE KEY"
	label_RSA_PRIVATE_KEY = "RSA PRIVATE KEY"
	label_CERTIFICATE     = "CERTIFICATE"
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

	snsTopicArn string
	// bucket_site        string
	// bucket_letsencrypt string
	// cloudfrontId       []string

	site Site

	ctx context.Context
}

func main() {
	lambda.Start(Handler)
}

type AcmeState struct {
	// bucket to store acme account credentials
	Bucket string
	// prefix to use in the keys for credential files
	KeyPrefix string
}

type Site struct {
	Contacts  []string
	AcmeState AcmeState
	Domains   []Domain
}

func (self *Site) Names() []string {
	names := []string{}
	for _, d := range self.Domains {
		names = append(names, d.Name)
	}
	return names
}

type Domain struct {
	// domain name
	Name string
	// bucket name
	Bucket string
	// cloudfront id
	CloudFrontID string
}

func newFetcher(ctx context.Context) (*fetcher, error) {
	region := "us-east-1"

	self := &fetcher{}
	self.ctx = ctx

	self.contact = "mailto:charles@cstrahan.com"

	self.site = Site{
		Contacts: []string{"mailto:charles@cstrahan.com"},
		AcmeState: AcmeState{
			Bucket:    "XXX",
			KeyPrefix: "letsencrypt",
		},
		Domains: []Domain{
			Domain{
				Name:         "www.cstrahan.com",
				Bucket:       "www.cstrahan.com",
				CloudFrontID: "XXX",
			},
			Domain{
				Name: "cstrahan.com",
				//Bucket:       "cstrahan.com",
				Bucket:       "www.cstrahan.com",
				CloudFrontID: "XXX",
			},
		},
	}

	self.awsSession = session.New(&aws.Config{Region: aws.String(region)})
	self.cloudfront = cloudfront.New(self.awsSession)
	self.iam = iam.New(self.awsSession)
	self.s3 = s3.New(self.awsSession)
	self.sns = sns.New(self.awsSession)

	// TODO: handle this correctly; don't hardcode
	self.snsTopicArn = "XXX"

	// ACME init
	log.Println("Fetching user key file")
	var keyPEM []byte
	keyPEMptr, err := self.loadFile(self.site.AcmeState.Bucket, self.site.AcmeState.KeyPrefix, USER_KEY_FILE)
	var key *ecdsa.PrivateKey
	if err != nil {
		return nil, err
	} else if keyPEMptr != nil {
		log.Println("User key found; reading key")
		key, err = readKey([]byte(*keyPEMptr))
		if err != nil {
			return nil, err
		}
	} else {
		log.Println("User key NOT found; creating new key")
		key, err = newKey()
		if err != nil {
			return nil, err
		}

		keyPEM, err = keyToPEM(key)
		if err != nil {
			return nil, err
		}

		log.Println("Saving user key")
		err = self.saveFile(self.site.AcmeState.Bucket, self.site.AcmeState.KeyPrefix, USER_KEY_FILE, string(keyPEM))
	}

	self.client = &acme.Client{
		Key: key,
		// "https://acme-v01.api.letsencrypt.org/directory",
		// "https://acme-staging.api.letsencrypt.org/directory",
		DirectoryURL: "https://acme-v01.api.letsencrypt.org/directory",
		//DirectoryURL: "https://acme-staging.api.letsencrypt.org/directory",
	}

	log.Println("Fetching user account file")
	var acct *acme.Account
	acctJSONptr, err := self.loadFile(self.site.AcmeState.Bucket, self.site.AcmeState.KeyPrefix, USER_ACCOUNT_FILE)
	if err != nil {
		return nil, err
	} else if acctJSONptr != nil {
		log.Println("User account file found; reading account")
		err = json.Unmarshal([]byte(*acctJSONptr), &acct)
		if err != nil {
			return nil, err
		}

		log.Println("Fetching ACME registration for user: " + acct.URI)
		acct, err = self.client.GetReg(self.ctx, acct.URI)

		if e, ok := err.(*acme.Error); ok && e.StatusCode == 403 {
			// If we get an error like this:
			//   403 urn:acme:error:unauthorized: No registration exists matching provided key
			//
			// That means the URI we had on file must have been for a previous key.
			// This would happen if the key gets written to S3 before we can successfully
			// register and save the new account. Just create a new account then.
			log.Println("No user exists with this key; creating new account")
			acct = &acme.Account{Contact: []string{self.contact}}

			acct, err = self.client.Register(self.ctx, acct, acme.AcceptTOS)
		} else if err != nil {
			return nil, err
		}
	} else {
		log.Println("User account file NOT found; creating new account")
		acct = &acme.Account{Contact: []string{self.contact}}
		acct, err = self.client.Register(self.ctx, acct, acme.AcceptTOS)

		if err != nil {
			if e, ok := err.(*acme.Error); ok && e.StatusCode == 409 {
				// If the server already has a registration object with the provided
				// account key, then it MUST return a 409 (Conflict) response and
				// provide the URI of that registration in a Location header field.
				// This allows a client that has an account key but not the
				// corresponding registration URI to recover the registration URI.
				uri := e.Header.Get("Location")
				log.Println("Saved account URI was mistaken; fetching this account instead: " + uri)
				acct, err = self.client.GetReg(self.ctx, uri)
				if err != nil {
					return nil, err
				}
			} else {
				// completely unexpected error
				return nil, err
			}
		}
	}

	// aggree to any new terms
	if acct.AgreedTerms != acct.CurrentTerms {
		acct.AgreedTerms = acct.CurrentTerms
	}

	// for now, we'll always update an existing account
	// TODO: how should this be handled ideally?
	log.Println("Updating ACME account registration")
	acct, err = self.client.UpdateReg(self.ctx, acct)
	if err != nil {
		return nil, err
	}

	acctJSON, err := json.MarshalIndent(acct, "", "  ")
	if err != nil {
		return nil, err
	}

	log.Println("Saving user account file")
	err = self.saveFile(self.site.AcmeState.Bucket, self.site.AcmeState.KeyPrefix, USER_ACCOUNT_FILE, string(acctJSON))
	if err != nil {
		return nil, err
	}

	self.acct = acct

	return self, nil
}

// lambda entry point
func Handler(ctx context.Context, request Request) (Response, error) {
	log.Println("Initializing ACME client")
	fetcher, err := newFetcher(ctx)
	if err != nil {
		log.Println("FAILURE:\n" + err.Error())
		return Response{}, err
	}

	err = fetcher.updateCert()
	if err != nil {
		log.Println("FAILURE:\n" + err.Error())
		return Response{}, err
	}

	return Response{}, err
}

func (self *fetcher) updateCert() error {
	log.Println("Updating certificate")
	certKey, err := newRSAKey()
	if err != nil {
		return err
	}

	keypem, err := rsaKeyToPEM(certKey)
	if err != nil {
		return err
	}

	// TODO: delete this
	self.saveFile(self.site.AcmeState.Bucket, self.site.AcmeState.KeyPrefix, "key.pem", string(keypem))

	req := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: self.site.Domains[0].Name},
	}
	if len(self.site.Domains) > 1 {
		req.DNSNames = self.site.Names()
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, certKey)
	if err != nil {
		return err
	}

	// initiate challenges for all domains
	log.Println("Initiating challenges for domains")
	for _, domain := range self.site.Domains {
		ctx, cancel := context.Background(), func() {}
		defer cancel()
		err := self.authz(ctx, self.client, domain)
		if err != nil {
			return err
		}
	}

	// done with challenge, get cert.
	log.Println("All challenges satisfied; creating certificate")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	derCert, curl, err := self.client.CreateCert(ctx, csr, certExpiry, true /*bundle*/)
	_ = curl
	if err != nil {
		log.Fatalf("cert: %v", err)
	}

	log.Println("PEM encoding certificate")
	// first block is our cert
	buf := new(bytes.Buffer)
	//pemcert := pem.EncodeToMemory(&pem.Block{Type: label_CERTIFICATE, Bytes: derCert[0]})
	err = pem.Encode(buf, &pem.Block{Type: label_CERTIFICATE, Bytes: derCert[0]})
	if err != nil {
		return err
	}

	pemcert := buf.Bytes()
	buf = new(bytes.Buffer)

	// TODO: delete this
	self.saveFile(self.site.AcmeState.Bucket, self.site.AcmeState.KeyPrefix, "cert.pem", string(pemcert))

	// subsequent blocks are the trust chain
	var pemchain []byte
	for idx, b := range derCert[1:] {
		log.Printf("PEM encoding trust chain (%v/%v)\n", idx+1, len(derCert[1:]))

		//b = pem.EncodeToMemory(&pem.Block{Type: label_CERTIFICATE, Bytes: b})
		//pemchain = append(pemchain, b...)

		pem.Encode(buf, &pem.Block{Type: label_CERTIFICATE, Bytes: b})
		if err != nil {
			return err
		}
	}
	pemchain = buf.Bytes()
	buf = new(bytes.Buffer)

	// TODO: delete this
	self.saveFile(self.site.AcmeState.Bucket, self.site.AcmeState.KeyPrefix, "chain.pem", string(pemchain))

	siteId := "cfd-" + self.site.Domains[0].Name
	certname := siteId + "_" + time.Now().Format("20060102_150405")

	log.Println("Uploading IAM certificate")
	certId, certArn, err := self.iamUploadCert(certname, pemcert, keypem, pemchain)
	if err != nil {
		return err
	}

	for _, domain := range self.site.Domains {
		log.Println("Configuring CloudFront distribution " + domain.CloudFrontID + " (for domain " + domain.Name + ") to use the certificate")
		err = self.cloudfrontConfigureCert(domain.CloudFrontID, certId, certArn)
		if err != nil {
			return err
		}
	}

	return nil
}

func (self *fetcher) authz(ctx context.Context, client *acme.Client, domain Domain) error {
	log.Println("Requesting challenge for " + domain.Name)
	z, err := self.client.Authorize(ctx, domain.Name)
	if err != nil {
		return err
	}
	if z.Status == acme.StatusValid {
		log.Println("Challenge already fulfilled for this domain")
		return nil
	}

	// pick out the http-01 challenge
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

	// fulfill http-01 challenge
	err = self.solveS3Challenge(chal, domain.Bucket)
	if err != nil {
		return err
	}

	// acknowledge challenge and wait
	log.Println("Acknowledging challenge")
	if _, err := self.client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept challenge: %v", err)
	}
	log.Println("Waiting for authorization")
	_, err = self.client.WaitAuthorization(ctx, z.URI)
	return err
}

// TODO: support dnsimple for dns-01 challenges

func (self *fetcher) iamUploadCert(certname string, pemcert []byte, pemkey []byte, pemchain []byte) (certid string, certarn string, err error) {
	newcert, err := self.iam.UploadServerCertificate(
		&iam.UploadServerCertificateInput{
			Path:                  aws.String("/cloudfront/"),
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
	name := *newcert.ServerCertificateMetadata.ServerCertificateName

	log.Println("Uploaded cert ID: " + certid)
	log.Println("             ARN: " + certarn)
	log.Println("            name: " + name)

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
	for retries := 10; retries > 0; retries -= 1 {
		log.Println("Attempting to deleting outdated IAM cert")
		_, err := self.iam.DeleteServerCertificate(
			&iam.DeleteServerCertificateInput{
				ServerCertificateName: aws.String(certname),
			},
		)
		if err == nil {
			// done
			log.Println("Successfully deleted outdated IAM cert")
			return
		} else if isErr(err, iam.ErrCodeDeleteConflictException) {
			// might take a while for a cert to stop being in use
			log.Println("Certificate still in use; retrying in 5 seconds")
			time.Sleep(5 * time.Second)
		} else {
			log.Println("Unknown error occurred while deleting certificate '" + certname + "'")
			log.Println(err.Error())
			self.emailNotify(
				"Unable to delete certificate",
				"Failed to delete the certificate '"+certname+"'; unkown error",
			)
			return
		}
	}

	log.Println("Failed to delete certificate '" + certname + "'; still in use")
	self.emailNotify(
		"Unable to delete certificate",
		"Failed to delete the certificate '"+certname+"'; still in use",
	)
}

func (self *fetcher) cloudfrontConfigureCert(cloudfrontId string, certId string, certArn string) error {
	log.Println("Fetching existing CloudFront distribution config")
	res, err := self.cloudfront.GetDistributionConfig(&cloudfront.GetDistributionConfigInput{Id: aws.String(cloudfrontId)})
	if err != nil {
		return err
	}

	cfg := res.DistributionConfig
	// TODO: this is going to fail if there wasn't an existing cert, isn't it?
	oldId := *cfg.ViewerCertificate.IAMCertificateId

	cfg.ViewerCertificate.CloudFrontDefaultCertificate = aws.Bool(false)
	cfg.ViewerCertificate.IAMCertificateId = aws.String(certId)
	cfg.ViewerCertificate.ACMCertificateArn = nil
	cfg.ViewerCertificate.MinimumProtocolVersion = aws.String("TLSv1")
	cfg.ViewerCertificate.SSLSupportMethod = aws.String("sni-only")

	for retries := 10; retries > 0; retries -= 1 {
		log.Println("Updating CloudFront distribution config")
		_, err = self.cloudfront.UpdateDistribution(
			&cloudfront.UpdateDistributionInput{
				DistributionConfig: cfg,
				Id:                 aws.String(cloudfrontId),
				IfMatch:            res.ETag,
			},
		)
		if err != nil && isErr(err, cloudfront.ErrCodeInvalidViewerCertificate) {
			// ErrCodeInvalidViewerCertificate might mean that the uploaded cert isn't available yet
			// (due to eventual consistency in this corner of the AWS APIs).
			// Retry a couple more times, under the assumption that's what's going on.
			// Sadly, this error code could mean one of many things, and it's impossible to
			// know exactly what's going on. Blech.
			// https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html
			if retries > 1 {
				log.Println("Couldn't update CloudFront distribution; retrying in 5 seconds")
				time.Sleep(5 * time.Second)
				continue
			} else {
				// Assume something else is going
				// (e.g. the certificate was malformed; somehow not in the right region; used a EC key; used a RSA key > 2048 bits; etc)
				return err
			}
		} else if err != nil {
			return err
		} else {
			// Succeeded
			break
		}
	}

	log.Println("Looking for outdated IAM cert to delete with ID: " + oldId)
	certMeta, err := self.iamFindCertById(oldId)
	if err != nil {
		return err
	} else if certMeta == nil {
		log.Println("No cert found with ID: '" + oldId)
	} else {
		log.Println("IAM Certificate found with name: '" + *certMeta.ServerCertificateName)
		self.iamDeleteCert(*certMeta.ServerCertificateName)
	}

	return nil
}

func (self *fetcher) solveS3Challenge(chal *acme.Challenge, bucket string) error {
	filename := self.client.HTTP01ChallengePath(chal.Token)

	tok, err := self.client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return err
	}

	log.Println("Saving challenge response file to S3")
	body := bytes.NewReader([]byte(tok))
	expires := time.Now().Add(time.Hour * 24 * 3)
	_, err = self.s3.PutObject(&s3.PutObjectInput{
		Bucket:  aws.String(bucket),
		Key:     aws.String(filename),
		Body:    body,
		Expires: &expires,
	})
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

	return err != nil, err
}

func (self *fetcher) saveFile(bucket string, directory string, filename string, content string) error {
	body := bytes.NewReader([]byte(content))

	_, err := self.s3.PutObject(
		&s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(directory + "/" + filename),
			Body:   body,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

// Fetch the file in the given directory.
// Returns nil if the file doesn't exist.
// All other S3 errors are returned directly.
func (self *fetcher) loadFile(bucket string, directory string, filename string) (*string, error) {
	key := directory + "/" + filename

	obj, err := self.s3.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
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
	_, err := self.sns.Publish(
		&sns.PublishInput{
			TopicArn: aws.String(self.snsTopicArn),
			Subject:  aws.String("[Lambda-LetsEncrypt] " + subject),
			Message:  aws.String(message),
		},
	)
	if err != nil {
		log.Println("Email notification via SNS failed:\n" + err.Error())
	}
}

func isErr(err error, awsErrType string) bool {
	if x, ok := err.(awserr.Error); ok {
		return x.Code() == awsErrType
	}

	return false
}

// PEM encode the given key
func keyToPEM(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	b := &pem.Block{Type: label_EC_PRIVATE_KEY, Bytes: der}
	err = pem.Encode(buf, b)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// PEM encode the given key
func rsaKeyToPEM(k *rsa.PrivateKey) ([]byte, error) {
	der := x509.MarshalPKCS1PrivateKey(k)
	buf := new(bytes.Buffer)
	b := &pem.Block{Type: label_RSA_PRIVATE_KEY, Bytes: der}
	err := pem.Encode(buf, b)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func newRSAKey() (*rsa.PrivateKey, error) {
	// CloudFront only supports RSA keys, and they must be 2048 bits.
	return rsa.GenerateKey(rand.Reader, 2048)
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
