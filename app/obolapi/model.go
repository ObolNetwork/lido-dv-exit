// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"encoding/json"
	"fmt"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"

	"github.com/ObolNetwork/lido-dv-exit/app/util"
)

const (
	// sszMaxExits is the maximum amount of exit messages in an array.
	sszMaxExits = 65536

	// sszLenPubKey is the length of a BLS validator public key
	sszLenPubKey = 48
)

// partialExitRequest represents the blob of data sent to the Obol API server, which is stored in the backend awaiting
// aggregation.
// Signature is the EC signature of partialExits's hash tree root done with the Charon node identity key.
type partialExitRequest struct {
	unsignedPartialExitRequest
	Signature []byte `json:"signature"`
}

// partialExitRequestDTO is partialExitRequest, but for serialization on the wire.
type partialExitRequestDTO struct {
	unsignedPartialExitRequest
	Signature string `json:"signature"`
}

func (p *partialExitRequest) UnmarshalJSON(bytes []byte) error {
	var dto partialExitRequestDTO

	if err := json.Unmarshal(bytes, &dto); err != nil {
		//nolint: wrapcheck // caller will wrap this error
		return err
	}

	sigBytes, err := util.K1SignatureToBytes(dto.Signature)
	if err != nil {
		//nolint: wrapcheck // caller will wrap this error
		return err
	}

	p.unsignedPartialExitRequest = dto.unsignedPartialExitRequest
	p.Signature = sigBytes

	return nil
}

func (p partialExitRequest) MarshalJSON() ([]byte, error) {
	dto := partialExitRequestDTO{
		unsignedPartialExitRequest: p.unsignedPartialExitRequest,
		Signature:                  fmt.Sprintf("%#x", p.Signature),
	}

	//nolint: wrapcheck // caller will wrap this error
	return json.Marshal(dto)
}

// unsignedPartialExitRequest represents an unsigned blob of data sent to the Obol API server, which is stored in the backend awaiting
// aggregation.
type unsignedPartialExitRequest struct {
	PartialExits partialExits `json:"partial_exits"`
	ShareIdx     uint64       `json:"share_idx,omitempty"`
}

func (p unsignedPartialExitRequest) GetTree() (*ssz.Node, error) {
	node, err := ssz.ProofTree(p)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return node, nil
}

func (p unsignedPartialExitRequest) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(p)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (p unsignedPartialExitRequest) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	if err := p.PartialExits.HashTreeRootWith(hh); err != nil {
		return errors.Wrap(err, "hash tree root with")
	}

	hh.PutUint64(p.ShareIdx)

	hh.Merkleize(indx)

	return nil
}

// partialExits is an array of ExitMessage that have been signed with a partial key.
type partialExits []ExitBlob

func (p partialExits) GetTree() (*ssz.Node, error) {
	hash, err := ssz.ProofTree(p)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return hash, nil
}

func (p partialExits) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(p)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (p partialExits) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	num := uint64(len(p))
	for _, pe := range p {
		if err := pe.HashTreeRootWith(hh); err != nil {
			return err
		}
	}

	hh.MerkleizeWithMixin(indx, num, sszMaxExits)

	return nil
}

// fullExitResponse contains all partial signatures, epoch and validator index to construct a full exit message for
// a validator.
// Signatures are ordered by share index.
type fullExitResponse struct {
	Epoch          string                `json:"epoch"`
	ValidatorIndex eth2p0.ValidatorIndex `json:"validator_index"`
	Signatures     []string              `json:"signatures"`
}

// fullExitAuthBlob represents the data required by Obol API to download the full exit blobs.
type fullExitAuthBlob struct {
	LockHash        []byte
	ValidatorPubkey []byte
	ShareIndex      uint64
}

func (f fullExitAuthBlob) GetTree() (*ssz.Node, error) {
	node, err := ssz.ProofTree(f)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return node, nil
}

func (f fullExitAuthBlob) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(f)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (f fullExitAuthBlob) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	hh.PutBytes(f.LockHash)
	if err := putBytesN(hh, f.ValidatorPubkey, sszLenPubKey); err != nil {
		return errors.Wrap(err, "validator pubkey ssz")
	}
	hh.PutUint64(f.ShareIndex)

	hh.Merkleize(indx)

	return nil
}

// ExitBlob is an exit message alongside its BLS12-381 hex-encoded signature.
type ExitBlob struct {
	PublicKey         string                     `json:"public_key,omitempty"`
	SignedExitMessage eth2p0.SignedVoluntaryExit `json:"signed_exit_message"`
}

func (e ExitBlob) GetTree() (*ssz.Node, error) {
	node, err := ssz.ProofTree(e)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return node, nil
}

func (e ExitBlob) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(e)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (e ExitBlob) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	pkBytes, err := util.ValidatorPubkeyToBytes(e.PublicKey)
	if err != nil {
		return errors.Wrap(err, "pubkey to bytes")
	}

	// Field (0) 'PublicKey'
	hh.PutBytes(pkBytes)

	// Field (1) 'SignedExitMessage'
	if err := e.SignedExitMessage.HashTreeRootWith(hh); err != nil {
		return errors.Wrap(err, "signed exit message hash tree root")
	}

	hh.Merkleize(indx)

	return nil
}

// leftPad returns the byte slice left padded with zero to ensure a length of at least l.
func leftPad(b []byte, l int) []byte {
	for len(b) < l {
		b = append([]byte{0x00}, b...)
	}

	return b
}

// putByteList appends b as a ssz fixed size byte array of length n.
func putBytesN(h ssz.HashWalker, b []byte, n int) error {
	if len(b) > n {
		return errors.New("bytes too long", z.Int("n", n), z.Int("l", len(b)))
	}

	h.PutBytes(leftPad(b, n))

	return nil
}
