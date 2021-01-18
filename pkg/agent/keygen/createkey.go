package keygen

import (
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func newCachedKey(rw io.ReadWriter, template tpm2.Public, owner, parent, cachedHandle tpmutil.Handle) (*KeyInfo, error) {
	cachedPub, _, _, err := tpm2.ReadPublic(rw, cachedHandle)
	if err == nil {
		if cachedPub.MatchesTemplate(template) {
			cachedPubData, err := cachedPub.Encode()
			if err != nil {
				return nil, err
			}

			return &KeyInfo{
				Handle:      cachedHandle,
				Template:    template,
				Public:      cachedPub,
				PublicBlob:  cachedPubData,
				PrivateBlob: nil,
			}, nil
		}

		// Kick out old cached key if it does not match
		err = tpm2.EvictControl(rw, "", owner, cachedHandle, cachedHandle)
		if err != nil {
			return nil, err
		}
	}

	info, err := createPrimaryKey(rw, parent, template)
	if err != nil {
		return nil, err
	}

	// Flush the current handler (info.Handle) since the object will be
	// persisted at cachedHandler.
	defer tpm2.FlushContext(rw, info.Handle)

	err = tpm2.EvictControl(rw, "", owner, info.Handle, cachedHandle)
	if err != nil {
		return nil, err
	}

	info.Handle = cachedHandle
	return info, nil
}

func createPrimaryKey(rw io.ReadWriter, owner tpmutil.Handle, template tpm2.Public) (*KeyInfo, error) {
	handle, pubBlob, _, _, _, _, err := tpm2.CreatePrimaryEx(
		rw,
		owner,
		tpm2.PCRSelection{},
		"",
		"",
		template,
	)
	if err != nil {
		err = fmt.Errorf("tpm2.CreatePrimary failed: %w", err)
		return nil, err
	}

	pubArea, err := tpm2.DecodePublic(pubBlob)
	if err != nil {
		tpm2.FlushContext(rw, handle)
		err = fmt.Errorf("decoding public key failed: %w", err)
		return nil, err
	}

	return &KeyInfo{
		Handle:      handle,
		Template:    template,
		Public:      pubArea,
		PublicBlob:  pubBlob,
		PrivateBlob: nil,
	}, nil
}

func createLoadedKey(rw io.ReadWriter, owner tpmutil.Handle, template tpm2.Public) (*KeyInfo, error) {
	auth := tpm2.AuthCommand{
		Session:    tpm2.HandlePasswordSession,
		Attributes: tpm2.AttrContinueSession,
		Auth:       []byte{},
	}

	privBlob, pubBlob, _, _, _, err := tpm2.CreateKeyUsingAuth(
		rw,
		owner,
		tpm2.PCRSelection{},
		auth,
		"",
		template,
	)
	if err != nil {
		err = fmt.Errorf("tpm2.CreateKey failed: %w", err)
		return nil, err
	}

	pubArea, err := tpm2.DecodePublic(pubBlob)
	if err != nil {
		err = fmt.Errorf("decoding public key failed: %w", err)
		return nil, err
	}

	handle, _, err := tpm2.LoadUsingAuth(rw, owner, auth, pubBlob, privBlob)
	if err != nil {
		err = fmt.Errorf("tpm2.Load failed: %w", err)
		return nil, err
	}

	return &KeyInfo{
		Handle:      handle,
		Template:    template,
		Public:      pubArea,
		PublicBlob:  pubBlob,
		PrivateBlob: privBlob,
	}, nil
}
