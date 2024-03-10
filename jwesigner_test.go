package jwesigner_test

import (
	"context"
	"fmt"
	"strings"

	"github.com/bayugyug/commons"
	"github.com/bayugyug/jwesigner"
	"github.com/bayugyug/jwesigner/mock"
	"github.com/icrowley/fake"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("JWE Signer", func() {

	var (
		svc jwesigner.Creator
	)

	BeforeEach(func() {

	})

	AfterEach(func() {

	})

	Context("Init Service", func() {
		It("should return ok", func() {
			var (
				opts = jwesigner.Options{
					PublicKey:  mock.DummyPublicKey,
					PrivateKey: mock.DummyPrivateKey,
				}
			)

			svc = jwesigner.New(&opts)
			Expect(svc).NotTo(BeNil())

			svc.SetOption(&jwesigner.Options{
				PublicKey:  mock.DummyPublicKey,
				PrivateKey: mock.DummyPrivateKey,
			})
			rop := svc.GetOption()
			Expect(rop).NotTo(BeNil())

			prv := svc.GetRSAPrivateKey()
			Expect(prv).NotTo(BeNil())

			pub := svc.GetRSAPublicKey()
			Expect(pub).NotTo(BeNil())

			By("Init Service ok")
		})
	})

	Context("Encrypt/Decrypt message", func() {
		It("should return ok", func() {

			var (
				opts = jwesigner.Options{
					PublicKey:  mock.DummyPublicKey,
					PrivateKey: mock.DummyPrivateKey,
				}
			)

			svc = jwesigner.New(&opts)
			Expect(svc).NotTo(BeNil())

			for i := 1; i < 15; i++ {

				payload := fmt.Sprintf("test message: %s", fake.SentencesN(i+1))

				// Encrypt
				enc, err := svc.Encrypt(context.Background(), []byte(payload))
				log.Println("encrypted: ", len(enc), err)

				Expect(err).To(BeNil())
				Expect(len(enc)).To(BeNumerically(">", 0))

				// Decrypt
				plain, err := svc.Decrypt(context.Background(), enc)
				log.Println("decrypted: ", len(plain), err, string(plain))

				Expect(err).To(BeNil())
				Expect(strings.HasPrefix(string(plain), "test message:")).To(Equal(true))
			}

			By("Encrypt/Decrypt message ok")
		})
	})

	Context("Sign/Verify message", func() {
		It("should return ok", func() {

			var (
				opts = jwesigner.Options{
					PublicKey:  mock.DummyPublicKey,
					PrivateKey: mock.DummyPrivateKey,
				}
				payload  = fmt.Sprintf("test message: %s", fake.SentencesN(5))
				verified *jwesigner.Verified
			)

			svc = jwesigner.New(&opts)
			Expect(svc).NotTo(BeNil())

			// Sign
			sig, err := svc.Sign(context.Background(), []byte(payload))
			log.Println("sign: ", len(sig), err, "signature:", sig)

			Expect(err).To(BeNil())
			Expect(len(sig)).To(BeNumerically(">", 0))

			// Verify
			verified, err = svc.Verify(context.Background(), sig)
			log.Println("verify: ", err, verified)
			Expect(err).To(BeNil())
			Expect(verified).NotTo(BeNil())

			commons.JSONify("VERIFIED::DATA", verified)

			By("Sign/Verify message ok")
		})
	})

	Context("Encrypt/Sign & Decrypt/Verify", func() {
		It("should return ok", func() {

			var (
				opts = jwesigner.Options{
					PublicKey:  mock.DummyPublicKey,
					PrivateKey: mock.DummyPrivateKey,
				}
				payload  = fmt.Sprintf("test message: %s", fake.SentencesN(10))
				verified *jwesigner.Verified
			)

			svc = jwesigner.New(&opts)
			Expect(svc).NotTo(BeNil())

			// Encrypt
			enc, err := svc.Encrypt(context.Background(), []byte(payload))
			log.Println("encrypted: ", len(enc), err)

			Expect(err).To(BeNil())
			Expect(len(enc)).To(BeNumerically(">", 0))

			// Sign
			sig, err := svc.Sign(context.Background(), []byte(payload))
			log.Println("sign: ", len(sig), err, "signature:", sig)

			Expect(err).To(BeNil())
			Expect(len(sig)).To(BeNumerically(">", 0))

			// Decrypt
			plain, err := svc.Decrypt(context.Background(), enc)
			log.Println("decrypted: ", len(plain), err, string(plain))

			Expect(err).To(BeNil())
			Expect(strings.HasPrefix(string(plain), "test message:")).To(Equal(true))

			// Verify
			verified, err = svc.Verify(context.Background(), sig)

			log.WithFields(
				log.Fields{
					"\n\npayload":   payload,
					"\n\nencrypted": fmt.Sprintf("%s", enc),
					"\n\ndecrypted": string(plain),
					"\n\nsignature": sig,
					"\n\nverified":  err == nil,
					"\n\ndata":      verified,
					"\n\nerr":       err,
				}).Println("details")

			Expect(err).To(BeNil())
			Expect(verified).NotTo(BeNil())

			commons.JSONify("VERIFIED::DATA", verified)

			By("Encrypt/Sign & Decrypt/Verify ok")
		})
	})

})
