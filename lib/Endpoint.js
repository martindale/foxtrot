'use strict';

var util = require('util');
var EventEmitter = require('events').EventEmitter;

var bitcore = require('bitcore');
var PrivateKey = bitcore.PrivateKey;
var ECIES = require('bitcore-ecies');

function Endpoint(key) {
  if (!(this instanceof Endpoint)) return new Endpoint(key);
  this.key = key || new PrivateKey();
}
util.inherits(Endpoint, EventEmitter);

Endpoint.prototype.credentials = function(request) {
  //console.log('Endpoint.credentials request',  request );
  // TODO: request sometimes has a public key, sometimes not?
  var sender = ECIES().privateKey(this.key).publicKey(request.address);

  var message = Buffer.concat([this.key.publicKey, request.address, request.nonce]);
  return sender.encrypt(message);
};

Endpoint.prototype.isMatch = function(pubkey) {
  return this.key.publicKey.toString() === pubkey.toString();
};

module.exports = Endpoint;
