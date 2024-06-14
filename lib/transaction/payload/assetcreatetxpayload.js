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
const NULL_ADDRESS = "0000000000000000000000000000000000000000";
const BLSSIG_SIZE = constants.BLS_SIGNATURE_SIZE;

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
  if(isRoot)
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
    this.externalTxid = constants.NULL_HASH;
    this.externalConfirmations = 0;
    this.collateralAddress = Buffer.alloc(PUBKEY_ID_SIZE).toString("hex");
    this.externalPayoutScript = Buffer.alloc(0).toString("hex");
    this.network = options && options.network;

    if (options) {
      this.isRoot = options.isRoot;
      if(!this.isRoot) {
        this.assetName = options.rootName + '|' + options.assetName;
      } else {
        this.assetName = options.assetName;
      }
      this.rootId = options.rootId != null ? options.rootId : null;
      this.isUnique = parseInt(options.isUnique);
      this.maxMintCount = parseInt(options.maxMintCount);
      this.updatable = parseInt(options.updatable);
      this.decimalPoint = parseInt(options.decimalPoint);
      this.referenceHash = options.referenceHash;
      this.fee = parseInt(options.fee);
      this.type = parseInt(options.type);
      this.targetAddress = Address.fromString(options.targetAddress, this.network, "pubkeyhash").hashBuffer.toString("hex");
      this.ownerAddress = Address.fromString(options.ownerAddress, this.network, "pubkeyhash").hashBuffer.toString("hex");
      if(options.collateralAddress != null && options.collateralAddress != NULL_ADDRESS) {
        this.collateralAddress = Address.fromString(options.collateralAddress, this.network, "pubkeyhash").hashBuffer.toString("hex");
      }
      if(options.externalPayoutScript != null) {
        this.externalPayoutScript = Script.fromAddress(options.externalPayoutScript).toHex();
      }
      this.exChainType = options.exChainType != null ? parseInt(options.exChainType) : 0;
      this.externalTxid = options.externalTxid != null ? options.externalTxid : constants.NULL_HASH;
      this.externalConfirmations = options.externalConfirmations != null ? parseInt(options.externalConfirmations) : 0;
      this.issueFrequency = parseInt(options.issueFrequency);
      this.amount = parseInt(options.amount) * 1e8;
      this.inputsHash = options.inputsHash;
      if (options.payloadSig) {
        this.payloadSig = options.payloadSig;
      }
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
      var rootIdSize = payloadBufferReader.readVarintNum();
      payload.rootId = payloadBufferReader        
        .read(rootIdSize)
        .toString('utf8');
        var payloadSigSize = payloadBufferReader.readVarintNum();
      payload.payloadSig = payloadBufferReader
        .read(payloadSigSize)
        .toString('hex');
    }
    payload.exChainType = payloadBufferReader.readUInt16LE();
    var scriptPayoutSize = payloadBufferReader.readVarintNum();
    payload.externalPayoutScript = payloadBufferReader
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
    if(this.isRoot) {
      Preconditions.checkArgument(
        isAssetNameValid(this.assetName, this.isRoot),
        'Invalid assetName, ensure string parameters match criteria'
      );
    }

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
  };
  
  /**
   * Serializes payload to JSON
   * @param [options]
   * @param [options.network] - network for address serialization
   * @return {AssetCreateTxPayloadJSON}
   */
  AssetCreateTxPayload.prototype.toJSON = function toJSON(options) {
    var skipSignature =
      Boolean(options && options.skipSignature) || !Boolean(this.payloadSig);
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
      isRoot: this.isRoot,
      fee: this.fee,
      type: this.isRoot ? "root" : "sub",
      distributionType: getDistributionType(this.type),
      targetAddress: Address.fromPublicKeyHash(Buffer.from(this.targetAddress, "hex"), network).toString("hex"),
      ownerAddress: Address.fromPublicKeyHash(Buffer.from(this.ownerAddress, "hex"), network).toString("hex"),
      collateralAddress: this.collateralAddress !== NULL_ADDRESS 
        ? Address.fromPublicKeyHash(Buffer.from(this.ownerAddress, "hex"), network).toString("hex")
        : "N/A",
      issueFrequency: this.issueFrequency,
      amount: this.amount / 1e8,
      exChainType: this.exChainType,
      externalPayoutScript: this.externalPayoutScript !== "" ? this.externalPayoutScript : "N/A",
      externalTxid: this.externalTxid,
      externalConfirmations: this.externalConfirmations,
      inputsHash: this.inputsHash,
    };

    if (!this.isRoot) {
      payloadJSON.rootId = this.rootId;
      if (!skipSignature) {
        payloadJSON.payloadSig = this.payloadSig;
      }
    }
  
    return payloadJSON;
};
  
  /**
   * Serialize payload to buffer
   * @param [options]
   * @return {Buffer}
   */
  AssetCreateTxPayload.prototype.toBuffer = function toBuffer(options) {
    var skipSignature =
      Boolean(options && options.skipSignature) || !Boolean(this.payloadSig);
  
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
    payloadBufferWriter.write(Buffer.from(this.collateralAddress, 'hex'));
    payloadBufferWriter.writeUInt8(this.isRoot);
    if(!this.isRoot) {
      payloadBufferWriter.writeVarintNum(Buffer.from(this.rootId, 'utf8').length);
      payloadBufferWriter.write(Buffer.from(this.rootId, 'utf8'));
      if (!skipSignature) {
        var signatureBuf = Buffer.from(this.payloadSig, 'hex');
        payloadBufferWriter.writeVarintNum(signatureBuf.length);
        payloadBufferWriter.write(signatureBuf);
      }
    }
    payloadBufferWriter.writeUInt16LE(this.exChainType);
    payloadBufferWriter.writeVarintNum(Buffer.from(this.externalPayoutScript, 'hex').length);
    payloadBufferWriter.write(Buffer.from(this.externalPayoutScript, 'hex'));
    payloadBufferWriter.write(Buffer.from(this.externalTxid, 'hex').reverse());
    payloadBufferWriter.writeUInt16LE(this.externalConfirmations);
    payloadBufferWriter.write(Buffer.from(this.inputsHash, 'hex').reverse());

    return payloadBufferWriter.toBuffer();
};
  
AssetCreateTxPayload.prototype.copy = function copy() {
    return AssetCreateTxPayload.fromBuffer(this.toBuffer());
};
  
module.exports = AssetCreateTxPayload;
