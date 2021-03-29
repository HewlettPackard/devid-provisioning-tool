// (C) Copyright 2021 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
package main

import (
	"context"
	"fmt"

	"github.com/HewlettPackard/devid-provisioning-tool/proto/enrollapi"
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
