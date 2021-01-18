package main

import (
	"context"
	"fmt"

	"github.hpe.com/langbeck/tpm2-keys/proto/enrollapi"
	"google.golang.org/grpc"
)

type protocolError struct {
	Reason string
}

func (e protocolError) Error() string {
	return fmt.Sprintf("protocol error: %s", e.Reason)
}

var (
	errMissingChallenge      = protocolError{Reason: "missing challenge"}
	errMissingSignedResponse = protocolError{Reason: "missing signed response"}
)

type enrollStream struct {
	stream enrollapi.Enrollment_EnrollClient
}

func startEnrollStream(ctx context.Context, conn *grpc.ClientConn) (*enrollStream, error) {
	client := enrollapi.NewEnrollmentClient(conn)
	stream, err := client.Enroll(ctx)
	if err != nil {
		return nil, err
	}

	return &enrollStream{stream: stream}, nil
}

func (es enrollStream) sendSigningRequest(requestData, requestSig []byte) error {
	return es.stream.Send(&enrollapi.EnrollRequest{
		RequestOrResponse: &enrollapi.EnrollRequest_SigningRequest{
			SigningRequest: &enrollapi.RawSigningRequest{
				Data:      requestData,
				Signature: requestSig,
			},
		},
	})
}

func (es enrollStream) recvChallenge() (credentialBlob, secret []byte, err error) {
	msg, err := es.stream.Recv()
	if err != nil {
		err = fmt.Errorf("challenge receiving failed: %w", err)
		return
	}

	challenge := msg.GetChallenge()
	if challenge == nil {
		err = errMissingChallenge
		return
	}

	return challenge.CredentialBlob, challenge.Secret, nil
}

func (es enrollStream) sendChallengeResponse(resp []byte) error {
	return es.stream.Send(&enrollapi.EnrollRequest{
		RequestOrResponse: &enrollapi.EnrollRequest_ChallengeResponse{
			ChallengeResponse: resp,
		},
	})
}

func (es enrollStream) recvSignedCertificates() (attestCert, devIDCert []byte, err error) {
	msg, err := es.stream.Recv()
	if err != nil {
		return nil, nil, err
	}

	resp := msg.GetSigningResponse()
	if resp == nil {
		err = errMissingSignedResponse
		return
	}

	return resp.AttestationCertificate, resp.DevIDCertificate, nil
}
