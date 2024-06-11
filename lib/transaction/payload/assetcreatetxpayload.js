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

/**
 * @typedef {Object} AssetCreateTxPayloadJSON
 * @property {string} assetId
 * @property {string} assetName
 * @property {number} circulatingSupply
 * @property {number} mintCount
 * @property {number} maxMintCount
 * @property {string} ownerAddress
 * @property {number} isUnique
 * @property {number} updatable
 * @property {number} decimalPoint
 * @property {string} referenceHash
 * @property {number} type
 * @property {string} targetAddress
 * @property {number} issueFrequency
 * @property {number} amount
 * @property {string} distribution
 * @property {number} isRoot
 * @property {number} fee
 * @property {string} collateralAddress
 */

function GetDistributionType(t) {
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
 * // https://github.com/Raptor3um/raptoreum/blob/develop/src/assets/assets.cpp
 * @class AssetCreateTxPayload
 * @property {string} assetId
 * @property {string} assetName
 * @property {number} circulatingSupply
 * @property {number} mintCount
 * @property {number} maxMintCount
 * @property {string} ownerAddress
 * @property {number} isUnique
 * @property {number} updatable
 * @property {number} decimalPoint
 * @property {string} referenceHash
 * @property {number} type
 * @property {string} targetAddress
 * @property {number} issueFrequency
 * @property {number} amount
 * @property {number} isRoot
 * @property {number} fee
 * @property {string} collateralAddress
 */

function AssetCreateTxPayload(options) {
    AbstractPayload.call(this);

    this.isRoot = false;
    this.updatable = false;
    this.isUnique = false;
    this.decimalPoint = 0;

    if (options) {
      this.assetId = options.txid;
      this.circulatingSupply = options.amount;
      this.mintCount = options.mintCount;
      this.assetName = options.assetName;
      this.isRoot = options.isRoot || false;
      this.updatable = options.updatable || false;
      this.isUnique = options.isUnique || false;
      this.maxMintCount = options.maxMintCount;
      this.decimalPoint = options.decimalPoint || 0;
      this.referenceHash = options.referenceHash;
      this.fee = options.fee;
      this.type = options.type;
      var scriptTargetAddress = Address.fromString(
        options.targetAddress
      );
      this.targetAddress = Script.buildPublicKeyHashOut(scriptTargetAddress).getData().toString("hex");
      this.issueFrequency = options.issueFrequency;
      this.amount = options.amount * 1e8;
      var scriptOwnerAddress = Address.fromString(
        options.ownerAddress
      );
      this.ownerAddress = Script.buildPublicKeyHashOut(scriptOwnerAddress).getData().toString("hex");
      var scriptCollateralAddress = Address.fromString(
        options.collateralAddress
      );
      this.collateralAddress = Script.buildPublicKeyHashOut(scriptCollateralAddress).getData().toString("hex");
    }
}

AssetCreateTxPayload.prototype = Object.create(AbstractPayload.prototype);
AssetCreateTxPayload.prototype.constructor = AbstractPayload;

/* Static methods */

/**
 * Parse raw payload
 * @param {Buffer} rawPayload
 * @return {AssetCreateTxPayload}
 */
AssetCreateTxPayload.fromBuffer = function fromBuffer(rawPayload) {

    var payloadBufferReader = new BufferReader(rawPayload);
    var payload = new AssetCreateTxPayload();

    payload.assetId = payloadBufferReader
      .read(HASH_SIZE)
      .reverse()
      .toString('hex');
    payload.circulatingSupply = payloadBufferReader.readUInt64LEBN().toNumber();
    payload.mintCount = payloadBufferReader.readUInt16LE();
    var assetName = payloadBufferReader.readVarintNum();
    payload.assetName = payloadBufferReader.read(assetName).toString();
    payload.isRoot = payloadBufferReader.readUInt8();
    payload.updatable = payloadBufferReader.readUInt8();
    payload.isUnique = payloadBufferReader.readUInt8();
    payload.maxMintCount = payloadBufferReader.readUInt16LE();
    payload.decimalPoint = payloadBufferReader.readUInt8();
    var referenceHash = payloadBufferReader.readVarintNum();
    payload.referenceHash = payloadBufferReader.read(referenceHash).toString();
    payload.fee = payloadBufferReader.readUInt16LE();
    payload.type = payloadBufferReader.readUInt8();
    payload.targetAddress = payloadBufferReader.read(PUBKEY_ID_SIZE).toString('hex');
    payload.issueFrequency = payloadBufferReader.readUInt8();
    payload.amount = payloadBufferReader.readUInt64LEBN().toNumber();
    payload.ownerAddress = payloadBufferReader.read(PUBKEY_ID_SIZE).toString('hex');
    payload.collateralAddress = payloadBufferReader.read(PUBKEY_ID_SIZE).toString('hex');

    if (!payloadBufferReader.finished()) {
      throw new Error(
        'Failed to parse payload: raw payload is bigger than expected.'
      );
    }
  
    return payload;
};

/**
 * Create new instance of payload from JSON
 * @param {string|AssetCreateTxPayloadJSON} payloadJson
 * @return {AssetCreateTxPayload}
 */
AssetCreateTxPayload.fromJSON = function fromJSON(payloadJson) {
    var payload = new AssetCreateTxPayload(payloadJson);
    payload.validate();
    return payload;
};

/* Instance methods */

/**
 * Validate payload
 * @return {boolean}
 */
AssetCreateTxPayload.prototype.validate = function () {
    /*Preconditions.checkArgument(
      utils.isUnsignedInteger(this.version),
      'Expect version to be an unsigned integer'
    );*/
    /*
    Preconditions.checkArgument(
      utils.isHexaString(this.externalPayoutAddress),
      'Expect externalPayoutAddress to be a hex string'
    );
    */
    /*
    Preconditions.checkArgument(
      utils.isSha256HexString(this.externalTxid),
      'Expect externalTxid to be a hex string representing sha256 hash'
    );
    */
    /*Preconditions.checkArgumentType(
      this.externalConfirmations,
      'number',
      'externalConfirmations'
    );*/
    /*Preconditions.checkArgument(
      utils.isHexaString(this.inputsHash),
      'Expect inputsHash to be a hex string'
    );*/
  };
  
  /**
   * Serializes payload to JSON
   * @param [options]
   * @param [options.network] - network for address serialization
   * @return {AssetCreateTxPayloadJSON}
   */
  AssetCreateTxPayload.prototype.toJSON = function toJSON(options) {
    var network = options && options.network;
    this.validate();
    var payloadJSON = {
      assetId: this.assetId,
      assetName: this.assetName,
      circulatingSupply: this.circulatingSupply,
      mintCount: this.mintCount,
      maxMintCount: this.maxMintCount,
      ownerAddress: new Script(this.ownerAddress)
        .toAddress(network)
        .toString(),
      isUnique: this.isUnique,
      updatable: this.updatable,
      decimalPoint: this.decimalPoint,
      referenceHash: this.referenceHash,
      type: this.type,
      targetAddress: new Script(this.targetAddress)
        .toAddress(network)
        .toString(),
      issueFrequency: this.issueFrequency,
      amount: this.amount / 1e8,
      distribution: GetDistributionType(this.type),
      isRoot: this.isRoot,
      fee: this.fee,
      collateralAddress: new Script(this.collateralAddress)
        .toAddress(network)
        .toString(),
    };

    return payloadJSON;
};
  
  /**
   * Serialize payload to buffer
   * @param [options]
   * @return {Buffer}
   */
  AssetCreateTxPayload.prototype.toBuffer = function toBuffer(options) {
    this.validate();
  
    var payloadBufferWriter = new BufferWriter();
    payloadBufferWriter.write(Buffer.from(this.assetId, 'hex').reverse());
    payloadBufferWriter.writeUInt64LEBN(new BigNumber(this.circulatingSupply));
    payloadBufferWriter.writeUInt16LE(this.mintCount);
    var assetName = Buffer.from(this.name, "utf8");
    payloadBufferWriter.writeVarintNum(assetName.length);
    payloadBufferWriter.write(assetName);
    payloadBufferWriter.writeUInt8(this.isRoot);
    payloadBufferWriter.writeUInt8(this.updatable);
    payloadBufferWriter.writeUInt8(this.isUnique);
    payloadBufferWriter.writeUInt16LE(this.maxMintCount);
    payloadBufferWriter.writeUInt8(this.decimalPoint);
    var referenceHash = Buffer.from(this.referenceHash, "utf8");
    payloadBufferWriter.writeVarintNum(referenceHash.length);
    payloadBufferWriter.write(referenceHash);
    payloadBufferWriter.writeUInt16LE(this.fee);
    payloadBufferWriter.writeUInt8(this.type);
    payloadBufferWriter.write(Buffer.from(this.targetAddress, 'hex'));
    payloadBufferWriter.writeUInt8(this.issueFrequency);
    payloadBufferWriter.writeUInt64LEBN(new BigNumber(this.amount));
    payloadBufferWriter.write(Buffer.from(this.ownerAddress, 'hex'));
    payloadBufferWriter.write(Buffer.from(this.collateralAddress, 'hex'));

    return payloadBufferWriter.toBuffer();
};
  
AssetCreateTxPayload.prototype.copy = function copy() {
    return AssetCreateTxPayload.fromBuffer(this.toBuffer());
};
  
module.exports = AssetCreateTxPayload;
