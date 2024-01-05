package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/holiman/uint256"
	"io"
	"net/http"
)

type StakeRewardMethod string

const (
	PayToBalance StakeRewardMethod = "PAY_TO_BALANCE"
	Restake      StakeRewardMethod = "RESTAKE"
)

type StakeRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	ValidatorPublicKeyBase58Check  string            `safeForLogging:"true"`
	RewardMethod                   StakeRewardMethod `safeForLogging:"true"`
	StakeAmountNanos               *uint256.Int      `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type UnstakeRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	ValidatorPublicKeyBase58Check  string            `safeForLogging:"true"`
	UnstakeAmountNanos             *uint256.Int      `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type UnlockStakeRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	ValidatorPublicKeyBase58Check  string            `safeForLogging:"true"`
	StartEpochNumber               uint64            `safeForLogging:"true"`
	EndEpochNumber                 uint64            `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type StakeTxnResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

type StakeEntryResponse struct {
	StakerPublicKeyBase58Check    string
	ValidatorPublicKeyBase58Check string
	RewardMethod                  StakeRewardMethod
	StakeAmountNanos              *uint256.Int
	ExtraData                     map[string]string
}

type LockedStakeEntryResponse struct {
	StakerPublicKeyBase58Check    string
	ValidatorPublicKeyBase58Check string
	LockedAmountNanos             *uint256.Int
	LockedAtEpochNumber           uint64
	ExtraData                     map[string]string
}

func (fes *APIServer) Stake(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := StakeRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Stake: Problem parsing request body: %v", err))
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("Stake: TransactorPublicKeyBase58Check is required"))
		return
	}
	transactorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Stake: Problem decoding TransactorPublicKeyBase58Check %s: %v",
			requestData.TransactorPublicKeyBase58Check, err))
		return
	}

	// Convert ValidatorPublicKeyBase58Check to ValidatorPublicKeyBytes
	if requestData.ValidatorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("Stake: ValidatorPublicKeyBase58Check is required"))
		return
	}
	validatorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ValidatorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Stake: Problem decoding ValidatorPublicKeyBase58Check %s: %v",
			requestData.ValidatorPublicKeyBase58Check, err))
		return
	}

	// Convert reward method string to enum.
	var rewardMethod lib.StakingRewardMethod
	switch requestData.RewardMethod {
	case PayToBalance:
		rewardMethod = lib.StakingRewardMethodPayToBalance
		break
	case Restake:
		rewardMethod = lib.StakingRewardMethodRestake
		break
	default:
		_AddBadRequestError(ww, fmt.Sprintf("Stake: Invalid RewardMethod %s", requestData.RewardMethod))
		return
	}

	// Validate stake amount
	if !requestData.StakeAmountNanos.IsUint64() {
		_AddBadRequestError(ww, fmt.Sprint("Stake: StakeAmountNanos must be a uint64"))
		return
	}
	stakeAmountNanosUint64 := requestData.StakeAmountNanos.Uint64()
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Stake: Problem fetching utxoView: %v", err))
		return
	}
	balance, err := utxoView.GetDeSoBalanceNanosForPublicKey(transactorPublicKeyBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Stake: Problem fetching balance: %v", err))
		return
	}
	if stakeAmountNanosUint64 > balance {
		_AddBadRequestError(ww, fmt.Sprintf("Stake: Insufficient balance: %d", balance))
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Stake: Problem parsing ExtraData: %v", err))
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeStake,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprint("Stake: specified TransactionFees are invalid"))
		return
	}

	// Create transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateStakeTxn(
		transactorPublicKeyBytes,
		&lib.StakeMetadata{
			ValidatorPublicKey: lib.NewPublicKey(validatorPublicKeyBytes),
			RewardMethod:       rewardMethod,
			StakeAmountNanos:   requestData.StakeAmountNanos,
		},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Stake: Problem creating transaction: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("Stake: Problem serializing transaction: %v", err))
		return
	}

	// TODO: do we need to specify the stake amount in the spend amount nanos?
	res := StakeTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "Stake: Problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) Unstake(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UnstakeRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Unstake: Problem parsing request body: %v", err))
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("Unstake: TransactorPublicKeyBase58Check is required"))
		return
	}
	transactorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Unstake: Problem decoding TransactorPublicKeyBase58Check %s: %v",
			requestData.TransactorPublicKeyBase58Check, err))
		return
	}

	// Convert ValidatorPublicKeyBase58Check to ValidatorPublicKeyBytes
	if requestData.ValidatorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("Unstake: ValidatorPublicKeyBase58Check is required"))
		return
	}
	validatorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ValidatorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Unstake: Problem decoding ValidatorPublicKeyBase58Check %s: %v",
			requestData.ValidatorPublicKeyBase58Check, err))
		return
	}

	// Validate unstake amount nanos
	if !requestData.UnstakeAmountNanos.IsUint64() {
		_AddBadRequestError(ww, fmt.Sprint("Unstake: UnstakeAmountNanos must be a uint64"))
		return
	}
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Unstake: Problem fetching utxoView: %v", err))
		return
	}
	// Get staker and validator PKIDs
	stakerPKID := utxoView.GetPKIDForPublicKey(transactorPublicKeyBytes)
	validatorPKID := utxoView.GetPKIDForPublicKey(validatorPublicKeyBytes)
	stakeEntry, err := utxoView.GetStakeEntry(validatorPKID.PKID, stakerPKID.PKID)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Unstake: Problem fetching stake entry: %v", err))
		return
	}
	if requestData.UnstakeAmountNanos.Gt(stakeEntry.StakeAmountNanos) {
		_AddBadRequestError(ww, fmt.Sprint("Unstake: UnstakeAmountNanos cannot be greater than the current stake "+
			"amount"))
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Unstake: Problem parsing ExtraData: %v", err))
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeUnstake,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprint("Unstake: specified TransactionFees are invalid"))
		return
	}

	// Create the transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUnstakeTxn(
		transactorPublicKeyBytes,
		&lib.UnstakeMetadata{
			ValidatorPublicKey: lib.NewPublicKey(validatorPublicKeyBytes),
			UnstakeAmountNanos: requestData.UnstakeAmountNanos,
		},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("Unstake: Problem serializing transaction: %v", err))
		return
	}

	res := StakeTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "Unstake: Problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) UnlockStake(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UnlockStakeRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UnlockStake: Problem parsing request body: %v", err))
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("UnlockStake: TransactorPublicKeyBase58Check is required"))
		return
	}
	transactorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UnlockStake: Problem decoding TransactorPublicKeyBase58Check %s: %v",
			requestData.TransactorPublicKeyBase58Check, err))
		return
	}

	// Convert ValidatorPublicKeyBase58Check to ValidatorPublicKeyBytes
	if requestData.ValidatorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("UnlockStake: ValidatorPublicKeyBase58Check is required"))
		return
	}
	validatorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ValidatorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UnlockStake: Problem decoding ValidatorPublicKeyBase58Check %s: %v",
			requestData.ValidatorPublicKeyBase58Check, err))
		return
	}

	// Validate start and end epoch
	if requestData.StartEpochNumber > requestData.EndEpochNumber {
		_AddBadRequestError(ww, fmt.Sprint("UnlockStake: StartEpochNumber cannot be greater than EndEpochNumber"))
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UnlockStake: Problem parsing ExtraData: %v", err))
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeUnlockStake,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprint("UnlockStake: specified TransactionFees are invalid"))
		return
	}

	// Create the transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUnlockStakeTxn(
		transactorPublicKeyBytes,
		&lib.UnlockStakeMetadata{
			ValidatorPublicKey: lib.NewPublicKey(validatorPublicKeyBytes),
			StartEpochNumber:   requestData.StartEpochNumber,
			EndEpochNumber:     requestData.EndEpochNumber,
		},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("UnlockStake: Problem serializing transaction: %v", err))
		return
	}

	res := StakeTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "UnlockStake: Problem encoding response as JSON")
		return
	}
}

// TODO: Implement the following GET endpoints:
// 1. GET stake entry given validator pub key & staker pub key
// 2. GET all stake entries given validator pub key
// 3. GET all stake entries given staker pub key
// 4. GET locked stake entry given validator pub key & staker pub key & locked at epoch number
// 5. GET all locked stake entries given validator pub key & staker pub key & optionally start and end epochs

// Other functions to implement.
// 1. _convertStakeEntryToResponse() helper function to convert a StakeEntry to a StakeEntryResponse.
// 2. _convertLockedStakeEntryToResponse() helper function to convert a LockedStakeEntry to a LockedStakeEntryResponse.
