// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/obolnetwork/charon/app/errors"

	"github.com/ObolNetwork/lido-dv-exit/app/util"
)

// PartialExitRequest represents the blob of data sent to the Obol API server, which is stored in the backend awaiting
// aggregation.
// Signature is the EC signature of PartialExits's hash tree root done with the Charon node identity key.
type PartialExitRequest struct {
	UnsignedPartialExitRequest
	Signature []byte `json:"signature"`
}

// UnsignedPartialExitRequest represents an unsigned blob of data sent to the Obol API server, which is stored in the backend awaiting
// aggregation.
type UnsignedPartialExitRequest struct {
	PartialExits PartialExits `json:"partial_exits"`
	ShareIdx     int          `json:"share_idx,omitempty"`
}

func (p UnsignedPartialExitRequest) GetTree() (*ssz.Node, error) {
	node, err := ssz.ProofTree(p)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return node, nil
}

func (p UnsignedPartialExitRequest) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(p)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (p UnsignedPartialExitRequest) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	if err := p.PartialExits.HashTreeRootWith(hh); err != nil {
		return errors.Wrap(err, "hash tree root with")
	}

	hh.PutUint64(uint64(p.ShareIdx))

	hh.Merkleize(indx)

	return nil
}

// PartialExits is an array of ExitMessage that have been signed with a partial key.
type PartialExits []ExitBlob

func (p PartialExits) GetTree() (*ssz.Node, error) {
	hash, err := ssz.ProofTree(p)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return hash, nil
}

func (p PartialExits) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(p)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (p PartialExits) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	for _, pexit := range p {
		if err := pexit.HashTreeRootWith(hh); err != nil {
			return errors.Wrap(err, "partial signature hash tree root")
		}
	}

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

// FullExitResponse contains all partial signatures, epoch and validator index to construct a full exit message for
// a validator.
// Signatures are ordered by share index.
type FullExitResponse struct {
	Epoch          string                `json:"epoch"`
	ValidatorIndex eth2p0.ValidatorIndex `json:"validator_index"`
	Signatures     []string              `json:"signatures"`
}

// FullExitAuthBlob represents the data required by Obol API to download the full exit blobs.
type FullExitAuthBlob struct {
	LockHash        []byte
	ValidatorPubkey []byte
	ShareIndex      int
}

func (f FullExitAuthBlob) GetTree() (*ssz.Node, error) {
	node, err := ssz.ProofTree(f)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return node, nil
}

func (f FullExitAuthBlob) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(f)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (f FullExitAuthBlob) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	hh.PutBytes(f.LockHash)
	hh.PutBytes(f.ValidatorPubkey)
	hh.PutUint64(uint64(f.ShareIndex))

	hh.Merkleize(indx)

	return nil
}
