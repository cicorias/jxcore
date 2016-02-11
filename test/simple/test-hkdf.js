// Copyright & License details are available under JXCORE_LICENSE file


var common = require('../common');
var assert = require('assert');


var crypto = require('crypto');


var pubKey = crypto.createECDH('secp256k1').generateKeys();
var ikm = crypto.randomBytes(8);
var ecdh = crypto.createECDH('secp256k1');


ecdh.generateKeys();
var salt = ecdh.computeSecret(pubKey);

crypto.generateHKDF2('sha256', salt, ikm, '', 32);

// HKDF('sha256', sxy, expirationBuffer).derive('', 32);

crypto.generateHKDF2('sha256', salt, ikm, '', 32);




