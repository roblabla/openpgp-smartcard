"use strict";

const { smartcard_open, smartcard_get_pub_key, smartcard_signature_for_hash, smartcard_list_ids } = require("./index.node");

class Smartcard {
  constructor(id) {
    this.card = smartcard_open(id);
  }

  static listIds() {
    return smartcard_list_ids();
  }

  publicKey() {
    return smartcard_get_pub_key(this.card);
  }

  signature_for_hash(hash, msg) {
    return smartcard_signature_for_hash(this.card, hash, msg);
  }
}

module.exports = Smartcard;
