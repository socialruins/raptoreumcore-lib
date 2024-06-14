/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

var utils = require('../../util/js');
var constants = require('../../constants');
var Preconditions = require('../../util/preconditions');
var BufferWriter = require('../../encoding/bufferwriter');
var BufferReader = require('../../encoding/bufferreader');
var AbstractPayload = require('./abstractpayload');
var Script = require('../../script');
var Address = require('../../address');
var BigNumber = require('bn.js');

var CURRENT_PAYLOAD_VERSION = 1;
var HASH_SIZE = constants.SHA256_HASH_SIZE;
var PUBKEY_ID_SIZE = constants.PUBKEY_ID_SIZE;
var CKEYID_SIZE = constants.PUBKEY_ID_SIZE;
var BLSSIG_SIZE = constants.BLS_SIGNATURE_SIZE;
const NULL_ADDRESS = "0000000000000000000000000000000000000000";

function getDistributionType(t) {
  switch (t) {
      case 0:
          return "manual";
      case 1:
          return "coinbase";
      case 2:
          return "address";
      case 3:
          return "schedule";
  }
  return "invalid";
}

/**
 * @typedef {Object} AssetUpTxPayloadJSON
 * @property {number} version	uint_16	Currently set to 1.
 * @property {string} assetId
 * @property {number} updatable
 * @property {string} referenceHash
 * @property {number} fee
 * @property {number} type
 * @property {string} targetAddress
 * @property {string} ownerAddress
 * @property {string} collateralAddress
 * @property {string} issueFrequency
 * @property {string} amount
 * @property {number} exChainType
 * @property {string} externalPayoutAddress
 * @property {string} externalTxid
 * @property {number} externalConfirmations
 * @property {string} inputsHash
 */

/**
 * // https://github.com/Raptor3um/raptoreum/blob/develop/src/assets/assets.cpp
 * @class AssetUpTxPayload
 * @property {number} version	uint_16	Currently set to 1.
 * @property {string} assetId
 * @property {number} updatable
 * @property {string} referenceHash
 * @property {number} fee
 * @property {number} type
 * @property {string} targetAddress
 * @property {string} ownerAddress
 * @property {string} collateralAddress
 * @property {string} issueFrequency
 * @property {string} amount
 * @property {number} exChainType
 * @property {string} externalPayoutAddress
 * @property {string} externalTxid
 * @property {number} externalConfirmations
 * @property {string} inputsHash
 */

function AssetUpTxPayload(options) {
  AbstractPayload.call(this);
  this.version = CURRENT_PAYLOAD_VERSION;
  this.externalTxid = constants.NULL_HASH;
  this.externalConfirmations = 0;
  this.collateralAddress = 0;

  if (options) {
    this.assetId = options.assetId;
    this.maxMintCount = parseInt(options.maxMintCount);
    this.updatable = parseInt(options.updatable);
    this.referenceHash = options.referenceHash;
    this.fee = parseInt(options.fee);
    this.type = parseInt(options.type);

    var scriptTargetAddress = Address.fromString(
      options.targetAddress
    );
    this.targetAddress = Script.buildPublicKeyHashOut(scriptTargetAddress).getData().toString("hex");

    var scriptOwnerAddress = Address.fromString(
      options.ownerAddress
    );
    this.ownerAddress = Script.buildPublicKeyHashOut(scriptOwnerAddress).getData().toString("hex");
    this.collateralAddress = options.collateralAddress != null 
      ? Script.fromAddress(options.collateralAddress).toHex()
      : 0x00;
    this.externalPayoutAddress = options.payoutAddress != null 
      ? Script.fromAddress(options.payoutAddress).toHex()
      : 0x00;
    this.exChainType = options.exChainType != null ? parseInt(options.exChainType) : 0;
    this.externalTxid = options.externalTxid != null ? options.externalTxid : constants.NULL_HASH;
    this.externalConfirmations = options.externalConfirmations != null ? parseInt(options.externalConfirmations) : 0;
    this.issueFrequency = parseInt(options.issueFrequency);
    this.amount = parseInt(options.amount) * 1e8;
    this.inputsHash = options.inputsHash;
    if (options.payloadSig) {
      this.payloadSig = options.payloadSig;
    }

    this.validate();
  }
}

AssetUpTxPayload.prototype = Object.create(AbstractPayload.prototype);
AssetUpTxPayload.prototype.constructor = AbstractPayload;

/* Static methods */

/**
 * Parse raw payload
 * @param {Buffer} rawPayload
 * @return {AssetUpTxPayload}
 */
AssetUpTxPayload.fromBuffer = function fromBuffer(rawPayload) {

    var payloadBufferReader = new BufferReader(rawPayload);
    var payload = new AssetUpTxPayload();
    var signatureSize = 0;

    payload.version = payloadBufferReader.readUInt16LE();
    payload.assetId = payloadBufferReader        
        .read(HASH_SIZE)
        .reverse()
        .toString('hex');
    payload.updatable = payloadBufferReader.readUInt8();
    var referenceHash = payloadBufferReader.readVarintNum();
    payload.referenceHash = payloadBufferReader.read(referenceHash).toString();
    payload.fee = payloadBufferReader.readUInt16LE();
    payload.type = payloadBufferReader.readUInt8();
    payload.targetAddress = payloadBufferReader.read(CKEYID_SIZE).toString('hex');
    payload.issueFrequency = payloadBufferReader.readUInt8();
    payload.maxMintCount = payloadBufferReader.readUInt16LE();
    payload.amount = payloadBufferReader.readUInt64LEBN().toNumber();
    payload.ownerAddress = payloadBufferReader.read(CKEYID_SIZE).toString('hex');
    var scriptCollateralSize = payloadBufferReader.readVarintNum();
    payload.collateralAddress = payloadBufferReader.read(scriptCollateralSize).toString('hex');
    payload.exChainType = payloadBufferReader.readUInt16LE();
    var scriptPayoutSize = payloadBufferReader.readVarintNum();
    payload.externalPayoutAddress = payloadBufferReader
      .read(scriptPayoutSize)
      .toString('hex');
    payload.externalTxid = payloadBufferReader
        .read(HASH_SIZE)
        .reverse()
        .toString('hex');
    payload.externalConfirmations = payloadBufferReader.readUInt16LE();
    payload.inputsHash = payloadBufferReader
        .read(HASH_SIZE)
        .reverse()
        .toString('hex');
    payload.payloadSig = payloadBufferReader
        .read(constants.BLS_SIGNATURE_SIZE)
        .toString('hex');
  
    if (!payloadBufferReader.finished()) {
      throw new Error(
        'Failed to parse payload: raw payload is bigger than expected.'
      );
    }

    payload.validate();
  
    return payload;
};

/**
 * Create new instance of payload from JSON
 * @param {string|AssetUpTxPayloadJSON} payloadJson
 * @return {AssetUpTxPayload}
 */
AssetUpTxPayload.fromJSON = function fromJSON(payloadJson) {
  return new AssetUpTxPayload(payloadJson);
};

/* Instance methods */

/**
 * Validate payload
 * @return {boolean}
 */
AssetUpTxPayload.prototype.validate = function () {
  Preconditions.checkArgument(
    utils.isUnsignedInteger(this.version),
    'Expect version to be an unsigned integer'
  );
  Preconditions.checkArgument(
    utils.isUnsignedInteger(this.updatable),
    'Expect updatable to be an unsigned integer'
  );
  Preconditions.checkArgument(
    utils.isUnsignedInteger(this.maxMintCount),
    'Expect maxmintcount to be an unsigned integer'
  );
  Preconditions.checkArgument(
    this.referenceHash.length <= 128,
    'Expect referenceHash to be lte 128'
  );
  Preconditions.checkArgument(
    utils.isUnsignedInteger(this.fee),
    'Expect fee to be an unsigned integer'
  );
  Preconditions.checkArgument(
    utils.isUnsignedInteger(this.type),
    'Expect type to be an unsigned integer'
  );
  Preconditions.checkArgument(
    utils.isHexaString(this.targetAddress),
    'Expect targetAddress to be a hex string'
  );
  Preconditions.checkArgument(
    utils.isHexaString(this.ownerAddress),
    'Expect ownerAddress to be a hex string'
  );
  Preconditions.checkArgument(
    utils.isUnsignedInteger(this.issueFrequency),
    'Expect issueFrequency to be an unsigned integer'
  );
  Preconditions.checkArgument(
    utils.isUnsignedInteger(this.amount),
    'Expect amount to be an unsigned integer'
  );
  Preconditions.checkArgument(
    utils.isHexaString(this.inputsHash),
    'Expect inputsHash to be a hex string'
  );
  if (this.payloadSig) {
    Preconditions.checkArgument(
      utils.isHexaString(this.payloadSig),
      'expected payloadSig to be a hex string'
    );
    Preconditions.checkArgument(
      this.payloadSig.length === constants.BLS_SIGNATURE_SIZE * 2,
      'Invalid payloadSig size'
    );
  }
};
  
  /**
   * Serializes payload to JSON
   * @param [options]
   * @param [options.network] - network for address serialization
   * @return {AssetUpTxPayloadJSON}
   */
  AssetUpTxPayload.prototype.toJSON = function toJSON(options) {
    var skipSignature =
      Boolean(options && options.skipSignature) || !Boolean(this.payloadSig);
    var network = options && options.network;
    this.validate();
    var payloadJSON = {
        version: this.version,
        assetId: this.assetId,
        updatable: this.updatable,
        referenceHash: this.referenceHash,
        fee: this.fee,
        type: this.type,
        targetAddress: new Script(this.targetAddress)
            .toAddress(network)
            .toString(),
        ownerAddress: new Script(this.ownerAddress)
            .toAddress(network)
            .toString(),
        collateralAddress: this.collateralAddress,
        issueFrequency: this.issueFrequency,
        amount: this.amount,
        exChainType: this.exChainType,
        externalPayoutAddress: this.externalPayoutAddress,
        externalTxid: this.externalTxid,
        externalConfirmations: this.externalConfirmations,
        inputsHash: this.inputsHash,
    };

    if (!skipSignature) {
      payloadJSON.payloadSig = this.payloadSig;
    }
  
    return payloadJSON;
};
  
  /**
   * Serialize payload to buffer
   * @param [options]
   * @return {Buffer}
   */
  AssetUpTxPayload.prototype.toBuffer = function toBuffer(options) {
    this.validate();
    var skipSignature =
      Boolean(options && options.skipSignature) || !Boolean(this.payloadSig);
  
    var payloadBufferWriter = new BufferWriter();

    payloadBufferWriter.writeUInt16LE(this.version);
    payloadBufferWriter.write(Buffer.from(this.assetId, 'hex').reverse());
    payloadBufferWriter.writeUInt8(this.updatable);
    var referenceHash = Buffer.from(this.referenceHash, "utf8");
    payloadBufferWriter.writeVarintNum(referenceHash.length);
    payloadBufferWriter.write(referenceHash);
    payloadBufferWriter.writeUInt16LE(this.fee);
    payloadBufferWriter.writeUInt8(this.type);
    payloadBufferWriter.write(Buffer.from(this.targetAddress, 'hex'));
    payloadBufferWriter.writeUInt8(this.issueFrequency);
    payloadBufferWriter.writeUInt16LE(this.maxMintCount);
    payloadBufferWriter.writeUInt64LEBN(new BigNumber(this.amount));
    payloadBufferWriter.write(Buffer.from(this.ownerAddress, 'hex'));
    payloadBufferWriter.write(Buffer.from(this.collateralAddress, 'hex'));
    payloadBufferWriter.writeUInt16LE(this.exChainType);
    //payloadBufferWriter.writeVarintNum(Buffer.from(this.externalPayoutAddress, 'hex').length);
    payloadBufferWriter.write(Buffer.from(this.externalPayoutAddress, 'hex'));
    payloadBufferWriter.write(Buffer.from(this.externalTxid, 'hex').reverse());
    payloadBufferWriter.writeUInt16LE(this.externalConfirmations);
    payloadBufferWriter.write(Buffer.from(this.inputsHash, 'hex').reverse());
    if (!skipSignature) {
      var signatureBuf = Buffer.from(this.payloadSig, 'hex');
      payloadBufferWriter.write(signatureBuf);
    } else {
      payloadBufferWriter.writeVarintNum(constants.EMPTY_SIGNATURE_SIZE);
    }
    return payloadBufferWriter.toBuffer();
};
  
AssetUpTxPayload.prototype.copy = function copy() {
    return AssetUpTxPayload.fromBuffer(this.toBuffer());
};
  
module.exports = AssetUpTxPayload;
