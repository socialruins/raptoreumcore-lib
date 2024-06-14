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
var BLSSIG_SIZE = constants.BLS_SIGNATURE_SIZE;

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
    if (options.payloadSig) {
      this.payloadSig = options.payloadSig;
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
  var assetId = payloadBufferReader.readVarintNum();
  payload.assetId = payloadBufferReader        
    .read(assetId)
    .toString('utf8');
  payload.fee = payloadBufferReader.readUInt16LE();
  payload.inputsHash = payloadBufferReader
    .read(HASH_SIZE)
    .reverse()
    .toString('hex');
  payload.payloadSig = payloadBufferReader
    .read(BLSSIG_SIZE)
    .toString('hex');

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
  return new AssetMintTxPayload(payloadJson);
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
  if (this.payloadSig) {
    Preconditions.checkArgument(
      utils.isHexaString(this.payloadSig),
      'expected payloadSig to be a hex string'
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
  var skipSignature =
    Boolean(options && options.skipSignature) || !Boolean(this.payloadSig);
  this.validate();

  var payloadJSON = {
    version: this.version,
    assetId: this.assetId,
    fee: this.fee,
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
AssetMintTxPayload.prototype.toBuffer = function toBuffer(options) {
  this.validate();
  var skipSignature =
    Boolean(options && options.skipSignature) || !Boolean(this.payloadSig);

  var payloadBufferWriter = new BufferWriter();

  payloadBufferWriter.writeUInt16LE(this.version);
  var assetId = Buffer.from(this.assetId, 'utf8');
  payloadBufferWriter.writeVarintNum(assetId.length);
  payloadBufferWriter.write(assetId);
  payloadBufferWriter.writeUInt16LE(this.fee);
  payloadBufferWriter.write(Buffer.from(this.inputsHash, 'hex').reverse());
  if (!skipSignature) {
    var signatureBuf = Buffer.from(this.payloadSig, 'hex');
    payloadBufferWriter.write(signatureBuf);
  }
  return payloadBufferWriter.toBuffer();
};

AssetMintTxPayload.prototype.copy = function copy() {
  return AssetMintTxPayload.fromBuffer(this.toBuffer());
};

module.exports = AssetMintTxPayload;
