"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class MessageCipher {
    constructor(sealKey, sealNonce, openKey, openNonce) {
        this.sealKey = sealKey;
        this.sealNonce = sealNonce;
        this.openKey = openKey;
        this.openNonce = openNonce;
    }
    encryptMessage(message) {
        return this.sealKey.encrypt(message, {
            iv: this.sealNonce,
        }).then(result => {
            incrementNonce(this.sealNonce);
            return {
                cipherText: result.cipherText,
                tag: result.tag
            };
        });
    }
    decryptMessage(message) {
        return this.openKey.decrypt(message.cipherText, this.openNonce, message.tag).then(decrypted => {
            incrementNonce(this.openNonce);
            return decrypted;
        });
    }
}
exports.MessageCipher = MessageCipher;
function incrementNonce(nonce) {
    for (let i = nonce.byteLength - 1; i >= 0; i--) {
        if (nonce[i] < 255) {
            nonce[i]++;
            return;
        }
        nonce[i] = 0;
    }
    throw new Error(`exhausted nonce of ${nonce.byteLength} bytes`);
}
