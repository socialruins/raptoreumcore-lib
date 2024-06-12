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

const name_root_characters = new RegExp('^[A-Z0-9._]{3,}$');
const name_sub_characters = new RegExp('^[a-zA-Z0-9 ]{3,}$');
const rtm_names = new RegExp('^RTM$|^RAPTOREUM$|^wRTM$|^WRTM$|^RTMcoin$|^RTMCOIN$');

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

function isAssetNameValid(name, isRoot) {
  if (name.length < 3 || name.length > 128) return false;
  if(isRoot === 1 || isRoot)
    return name_root_characters.test(name) && !rtm_names.test(name);
  else
    return name_sub_characters.test(name) && !rtm_names.test(name);
}

/**
 * @typedef {Object} AssetCreateTxPayloadJSON
 * @property {number} version	uint_16	Currently set to 1.
 * @property {string} name
 * @property {number} isUnique
 * @property {number} maxMintCount
 * @property {number} updatable
 * @property {number} decimalPoint
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
 * @class AssetCreateTxPayload
 * @property {number} version	uint_16	Currently set to 1.
 * @property {string} name
 * @property {number} isUnique
 * @property {number} maxMintCount
 * @property {number} updatable
 * @property {number} decimalPoint
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

function AssetCreateTxPayload(options) {
    AbstractPayload.call(this);
    this.version = CURRENT_PAYLOAD_VERSION;

    if (options) {
      this.isRoot = options.isRoot || 1;
      if(!this.isRoot) {
        this.assetName = options.rootName + '|' + options.assetName;
      } else {
        this.assetName = options.assetName;
      }
      this.rootId = options.rootId || null;
      this.isUnique = options.isUnique || 0;
      this.maxMintCount = options.maxMintCount || 1;
      this.updatable = options.updatable || 0;
      this.decimalPoint = options.decimalPoint || 0;
      this.referenceHash = options.referenceHash || "";
      this.fee = options.fee;
      this.type = options.type || 0;
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
        : '00';
      this.externalPayoutAddress = options.payoutAddress != null 
        ? Script.fromAddress(options.payoutAddress).toHex()
        : '00';
      this.exChainType = options.exChainType != null ? options.exChainType : 0;
      this.externalTxid = options.externalTxid != null ? options.externalTxid : constants.NULL_HASH;
      this.externalConfirmations = options.externalConfirmations != null ? options.externalConfirmations : 0;
      this.issueFrequency = options.issueFrequency || 0;
      this.amount = options.amount * 1e8;
      this.inputsHash = options.inputsHash;
      this.payloadSig = options.payloadSig;
      this.payloadSigSize = this.payloadSig
        ? Buffer.from(this.payloadSig, 'hex').length
        : 0;
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

    payload.version = payloadBufferReader.readUInt16LE();
    var assetName = payloadBufferReader.readVarintNum();
    payload.assetName = payloadBufferReader.read(assetName).toString();
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
    payload.isRoot = payloadBufferReader.readUInt8();
    if(!payload.isRoot) {
      payload.payloadSigSize = payloadBufferReader.readVarintNum();
      if (payload.payloadSigSize > 0) {
        payload.payloadSig = payloadBufferReader
          .read(payload.payloadSigSize)
          .toString('hex');
      }
    }
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
    Preconditions.checkArgument(
      utils.isUnsignedInteger(this.version),
      'Expect version to be an unsigned integer'
    );
    Preconditions.checkArgument(
      utils.isUnsignedInteger(this.isRoot),
      'Expect isroot to be an unsigned integer'
    );
    Preconditions.checkArgument(
      isAssetNameValid(this.assetName, this.isRoot),
      'Invalid assetName, ensure string parameters match criteria'
    );
    Preconditions.checkArgument(
      utils.isUnsignedInteger(this.isUnique),
      'Expect isUnique to be an unsigned integer'
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
      utils.isUnsignedInteger(this.decimalPoint)
        && this.decimalPoint <= 8,
      'Expect decimalpoint to be an unsigned integer in range 0-8'
    );
    Preconditions.checkArgument(
      this.referenceHash.length <= 128,
      'Expect referenceHash to be lte 128'
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
      utils.isSha256HexString(this.inputsHash),
      'Expect inputsHash to be a hex string'
    );
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
        version: this.version,
        assetName: this.assetName,
        isUnique: this.isUnique,
        maxMintCount: this.maxMintCount,
        updatable: this.updatable,
        decimalPoint: this.decimalPoint,
        referenceHash: this.referenceHash,
        fee: this.fee,
        type: this.isRoot ? "root" : "sub",
        distributionType: getDistributionType(this.type),
        targetAddress: new Script(this.targetAddress)
            .toAddress(network)
            .toString(),
        ownerAddress: new Script(this.ownerAddress)
            .toAddress(network)
            .toString(),
        collateralAddress: this.collateralAddress === '00' 
          ? "N/A" 
          : new Script(this.collateralAddress)
            .toAddress(network)
            .toString(),
        issueFrequency: this.issueFrequency,
        amount: this.amount / 1e8,
        exChainType: this.exChainType,
        externalPayoutAddress: this.externalPayoutAddress,
        externalTxid: this.externalTxid,
        externalConfirmations: this.externalConfirmations,
        inputsHash: this.inputsHash,
    };
  
    return payloadJSON;
};
  
  /**
   * Serialize payload to buffer
   * @param [options]
   * @return {Buffer}
   */
  AssetCreateTxPayload.prototype.toBuffer = function toBuffer(options) {
    var noSignature = !Boolean(this.payloadSig);
    var skipSignature = noSignature || (options && options.skipSignature);

    this.validate();
  
    var payloadBufferWriter = new BufferWriter();

    payloadBufferWriter.writeUInt16LE(this.version);
    var assetName = Buffer.from(this.assetName, "utf8");
    payloadBufferWriter.writeVarintNum(assetName.length);
    payloadBufferWriter.write(assetName);
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
    payloadBufferWriter.writeVarintNum(Buffer.from(this.collateralAddress, 'hex').length);
    payloadBufferWriter.write(Buffer.from(this.collateralAddress, 'hex'));
    payloadBufferWriter.writeUInt8(this.isRoot);
    if(!this.isRoot) {
      payloadBufferWriter.write(Buffer.from(this.rootId, "utf8"));
      if (!skipSignature && this.payloadSig) {
        payloadBufferWriter.writeVarintNum(
          Buffer.from(this.payloadSig, 'hex').length
        );
        payloadBufferWriter.write(Buffer.from(this.payloadSig, 'hex'));
      }
    }
    payloadBufferWriter.writeUInt16LE(this.exChainType);
    payloadBufferWriter.writeVarintNum(Buffer.from(this.externalPayoutAddress, 'hex').length);
    payloadBufferWriter.write(Buffer.from(this.externalPayoutAddress, 'hex'));
    payloadBufferWriter.write(Buffer.from(this.externalTxid, 'hex').reverse());
    payloadBufferWriter.writeUInt16LE(this.externalConfirmations);
    payloadBufferWriter.write(Buffer.from(this.inputsHash, 'hex').reverse());

    return payloadBufferWriter.toBuffer();
};
  
AssetCreateTxPayload.prototype.copy = function copy() {
    return AssetCreateTxPayload.fromBuffer(this.toBuffer());
};
  
module.exports = AssetCreateTxPayload;
