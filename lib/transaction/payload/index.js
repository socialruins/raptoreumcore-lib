/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

var Payload = require('./payload');

Payload.constants = require('../../constants');
//Payload.ProRegTxPayload = require('./proregtxpayload');
//Payload.ProUpRegTxPayload = require('./proupregtxpayload');
//Payload.ProUpRevTxPayload = require('./prouprevtxpayload');
//Payload.ProTxUpServPayload = require('./proupservtxpayload');
//Payload.SubTxCloseAccountPayload = require('./subtxcloseaccountpayload');
//Payload.SubTxRegisterPayload = require('./subtxregisterpayload');
//Payload.SubTxResetKeyPayload = require('./subtxresetkeypayload');
//Payload.SubTxTopupPayload = require('./subtxtopuppayload');
//Payload.SubTxTransitionPayload = require('./subtxtransitionpayload');
//Payload.CoinbasePayload = require('./coinbasepayload');
Payload.FutureTxPayload = require('./futuretxpayload');
//Payload.CommitmentTxPayload = require('./commitmenttxpayload');
Payload.AssetCreateTxPayload = require('./assetcreatetxpayload');
Payload.AssetUpTxPayload = require('./assetuptxpayload');
Payload.AssetMintTxPayload = require('./assetminttxpayload');

module.exports = Payload;
