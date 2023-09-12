/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

var utils = require('../../util/js');
var constants = require('../../constants');
var Preconditions = require('../../util/preconditions');
var BufferWriter = require('../../encoding/bufferwriter');
var BufferReader = require('../../encoding/bufferreader');
var AbstractPayload = require('./abstractpayload');
//var Script = require('../../script');
//var BigNumber = require('bn.js');

var CURRENT_PAYLOAD_VERSION = 1;
var HASH_SIZE = constants.SHA256_HASH_SIZE;