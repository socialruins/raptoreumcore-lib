const crypto = require('crypto');
const multihashing = require('node-multi-hashing');

/**
 * @typedef {multihashing} multihashing
 * @property {Object} errors
 * @property {function((string|Array|buffer), number, number): (string|Array)} digest
 */

/**
 * @typedef {Crypto} Crypto
 * @property {function(string, HashOptions): Hash} createHash
 */

/**
 * @typedef {DashCoreLibConfiguration} DashCoreLibConfiguration
 * @property {multihashing} [multihashing]
 * @property {Crypto} [crypto]
 */
const configuration = {
  multihashing,
  crypto
};

/**
 * Configures DashCore library
 * @param {DashCoreLibConfiguration} config
 */
const configure = (config) => {
  Object.assign(configuration, { ...config });
}

module.exports = {
  configuration,
  configure
}
