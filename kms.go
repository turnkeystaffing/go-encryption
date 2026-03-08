package encryption

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSAdapter wraps the AWS KMS SDK client to implement KMSClient.
type KMSAdapter struct {
	client *kms.Client
}

// NewKMSAdapter creates a KMSAdapter from an AWS KMS SDK client.
func NewKMSAdapter(client *kms.Client) *KMSAdapter {
	if client == nil {
		panic("encryption: NewKMSAdapter requires non-nil client")
	}
	return &KMSAdapter{client: client}
}

var _ KMSClient = (*KMSAdapter)(nil)

func (k *KMSAdapter) GenerateDataKey(ctx context.Context, keyID string) (plaintext, ciphertext []byte, err error) {
	output, err := k.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   &keyID,
		KeySpec: types.DataKeySpecAes256,
	})
	if err != nil {
		return nil, nil, err
	}
	return output.Plaintext, output.CiphertextBlob, nil
}

func (k *KMSAdapter) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	output, err := k.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: ciphertext,
	})
	if err != nil {
		return nil, err
	}
	return output.Plaintext, nil
}

// noopKMSClient is a KMSClient that returns errors for all operations.
// Used when KMS is disabled by feature flag so consumers never see a nil client.
type noopKMSClient struct{}

// NewNoopKMSClient creates a KMSClient that rejects all operations with
// a "service disabled" error.
func NewNoopKMSClient() KMSClient { return &noopKMSClient{} }

var _ KMSClient = (*noopKMSClient)(nil)

func (*noopKMSClient) GenerateDataKey(context.Context, string) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("kms: service disabled")
}

func (*noopKMSClient) Decrypt(context.Context, []byte) ([]byte, error) {
	return nil, fmt.Errorf("kms: service disabled")
}
