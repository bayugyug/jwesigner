# jwesigner
Package will securely Encrypt/Sign / Decrypt/Verify a req payload using RSA certificates 
- Prerequisite must have a valid RSA private/public certificates



## Workflow


### RSA Key Pairs ( at least 2048 bits )

            RSA (Rivest–Shamir–Adleman) encryption is one of the most widely used
            algorithms for secure data encryption.

#### RSA PublicKey

			remote public key ( client )
			
			used for verifying, the signature of the remote client
			
			shared by client to us
			
			is the public key pair of the remote client

#### RSA PrivateKey

			own local private key ( SELF )
			
			used for signing
			
			the remote client will verify it using the public key of this private key
			
			we will share the public key pair to the remote client


### Self sign RSA certificates
```shell script

# init vars
PREFIX=$(date '+%Y-%m-%d-%H%M%S')-$(printf "%04x-%04x" ${RANDOM} ${RANDOM})
PRIVKEY=/tmp/${PREFIX}-priv.pem
CACERT=/tmp/${PREFIX}-cacert.pem
DERCERT=/tmp/${PREFIX}-dercert.cer
PUBKEY=/tmp/${PREFIX}-pub.txt

# generate
openssl genrsa -out $PRIVKEY 4096
openssl req -new -x509 -key $PRIVKEY -out $CACERT -days 3650 -subj "/C=SG/ST='Singapore'/L='Singapore/O=Bayugismo/OU='Engineering'/CN=*.bayugismo.space"
openssl x509 -inform PEM -in $CACERT -outform DER -out $DERCERT
openssl x509 -inform der -in $DERCERT -noout -pubkey > $PUBKEY

# PUBLIC KEY must be in S3 bucket config
openssl rsa -pubin -in $PUBKEY | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'

# PRIVATE KEY must be in S3 bucket config
cat $PRIVKEY | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'

```


### How-To use the module/package
```go

import (
	"context"
	"fmt"
	"github.com/bayugyug/jwesigner"
	"github.com/bayugyug/jwesigner/mock"
	"github.com/icrowley/fake"
	log "github.com/sirupsen/logrus"
	"strings"
)




    var (
        opts = jwesigner.Options{
            PublicKey:  mock.DummyPublicKey,
            PrivateKey: mock.DummyPrivateKey,
        }
        payload = fmt.Sprintf("test message: %s", fake.SentencesN(10))
    )
    
    // init
    svc := jwesigner.New(&opts)
    
    
    // Encrypt payload
    enc, err := svc.Encrypt(context.Background(), []byte(payload))
    log.Println("encrypted: ", len(enc))
    
    // sanity check
    if err != nil{
        log.Errorln("failed:", err)
        return
    }

    // Sign the payload and return the signature
    sig, err := svc.Sign(context.Background(), []byte(payload))
    log.Println("sign: ", len(sig), "signature:", sig)
   
    // sanity check
    if err != nil{
        log.Errorln("failed:", err)
        return
    }

    // Decrypt the encrypted payload
    plain, err := svc.Decrypt(context.Background(), enc)
    log.Println("decrypted: ", len(plain), string(plain))

    // sanity check
    if err != nil{
        log.Errorln("failed:", err)
        return
    }

    // Verify check the authenticity of the decrypted payload and signature
    err = svc.Verify(context.Background(), sig)
    
    // dump
    log.WithFields(
                log.Fields{
                    "\npayload":   payload,
                    "\ndecrypted": string(plain),
                    "\nsignature": sig,
                    "\nverified":  err == nil,
                "\nerr":       err,
                }).Println("details")
```
