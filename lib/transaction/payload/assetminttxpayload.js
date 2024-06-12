/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

var utils = require('../../util/js');
var constants = require('../../constants');
var Preconditions = require('../../util/preconditions');
var BufferWriter = require('../../encoding/bufferwriter');
var BufferReader = require('../../encoding/bufferreader');
var AbstractPayload = require('./abstractpayload');

var CURRENT_PAYLOAD_VERSION = 1;
var HASH_SIZE = constants.SHA256_HASH_SIZE;

/**
 * @typedef {Object} AssetMintTxPayloadJSON
 * @property {number} version	uint_16	Currently set to 1.
 * @property {string} assetId
 * @property {number} fee - fee was paid for this mint in addition to miner fee. it is a whole non-decimal point value.
 * @property {string} inputsHash - replay protection
 */

/**
 * @class AssetMintTxPayload
 * @property {number} version	uint_16	Currently set to 1.
 * @property {string} assetId
 * @property {number} fee - fee was paid for this mint in addition to miner fee. it is a whole non-decimal point value.
 * @property {string} inputsHash - replay protection
 */

function AssetMintTxPayload(options) {
  AbstractPayload.call(this);
  this.version = CURRENT_PAYLOAD_VERSION;
  
  if (options) {
    this.assetId = options.assetId;
    this.fee = options.fee;
    this.inputsHash = options.inputsHash;
    if (payloadJSON.payloadSig) {
      this.payloadSig = payloadJSON.payloadSig;
    }
  }
}

AssetMintTxPayload.prototype = Object.create(AbstractPayload.prototype);
AssetMintTxPayload.prototype.constructor = AbstractPayload;

/* Static methods */

/**
 * Parse raw payload
 * @param {Buffer} rawPayload
 * @return {AssetMintTxPayload}
 */
AssetMintTxPayload.fromBuffer = function fromBuffer(rawPayload) {
  var payloadBufferReader = new BufferReader(rawPayload);
  var payload = new AssetMintTxPayload();

  payload.version = payloadBufferReader.readUInt16LE();
  payload.assetId = payloadBufferReader
    .read(HASH_SIZE)
    .reverse()
    .toString('hex');
  payload.fee = payloadBufferReader.readUInt16LE();
  payload.inputsHash = payloadBufferReader
    .read(HASH_SIZE)
    .reverse()
    .toString('hex');

  if (!payloadBufferReader.finished()) {
    signatureSize = payloadBufferReader.readVarintNum();
  }

  if (signatureSize > 0) {
    payload.payloadSig = payloadBufferReader
      .read(signatureSize)
      .toString('hex');
  }

  if (!payloadBufferReader.finished()) {
    throw new Error(
      'Failed to parse payload: raw payload is bigger than expected.'
    );
  }

  return payload;
};

/**
 * Create new instance of payload from JSON
 * @param {string|AssetMintTxPayloadJSON} payloadJson
 * @return {AssetMintTxPayload}
 */
AssetMintTxPayload.fromJSON = function fromJSON(payloadJson) {
  var payload = new AssetMintTxPayload(payloadJson);
  payload.validate();
  return payload;
};

/* Instance methods */

/**
 * Validate payload
 * @return {boolean}
 */
AssetMintTxPayload.prototype.validate = function () {
  Preconditions.checkArgument(
    utils.isUnsignedInteger(this.version),
    'Expect version to be an unsigned integer'
  );
  Preconditions.checkArgument(
    utils.isHexaString(this.assetId),
    'Expect assetId to be a hex string'
  );
  Preconditions.checkArgument(
    utils.isUnsignedInteger(this.fee),
    'Expect fee to be an unsigned integer'
  );
  Preconditions.checkArgument(
    utils.isHexaString(this.inputsHash),
    'Expect inputsHash to be a hex string'
  );
  if (Boolean(this.payloadSig)) {
    Preconditions.checkArgument(
      isHexString(this.payloadSig),
      'Expect payloadSig to be a hex string'
    );
    Preconditions.checkArgument(
      this.payloadSig.length * 2 !== BLSSIG_SIZE,
      "payloadSig size doesn't match BLS signature size"
    );
  }
};

/**
 * Serializes payload to JSON
 * @param [options]
 * @param [options.network] - network for address serialization
 * @return {AssetMintTxPayloadJSON}
 */
AssetMintTxPayload.prototype.toJSON = function toJSON(options) {
  //var network = options && options.network;
  this.validate();
  var payloadJSON = {
    version: this.version,
    assetId: this.assetId,
    fee: this.fee,
    inputsHash: this.inputsHash,
  };

  return payloadJSON;
};

/**
 * Serialize payload to buffer
 * @param [options]
 * @return {Buffer}
 */
AssetMintTxPayload.prototype.toBuffer = function toBuffer(options) {
  var skipSignature =
    Boolean(options && options.skipSignature) || !Boolean(this.payloadSig);

  this.validate();

  var payloadBufferWriter = new BufferWriter();

  payloadBufferWriter
    .writeUInt16LE(this.version)
    .write(Buffer.from(this.assetId, 'hex').reverse())
    .writeUInt16LE(this.fee)
    .write(Buffer.from(this.inputsHash, 'hex').reverse());

  if (!skipSignature) {
    var signatureBuf = Buffer.from(this.payloadSig, 'hex');
    payloadBufferWriter.writeVarintNum(signatureBuf.length);
    payloadBufferWriter.write(signatureBuf);
  } else {
    payloadBufferWriter.writeVarintNum(constants.EMPTY_SIGNATURE_SIZE);
  }

  return payloadBufferWriter.toBuffer();
};

AssetMintTxPayload.prototype.copy = function copy() {
  return AssetMintTxPayload.fromBuffer(this.toBuffer());
};

module.exports = AssetMintTxPayload;
