import {
    AESKey,
    AESEncryptOptions,
    importAESKey,
    RSAKeyPair
} from "ti-crypto";
import {
    encode,
    decode
} from "msgpack-lite";

export const VERSION: Version = {
    maj: 0,
    min: 0,
    pat: 0
}

export interface Version {
    maj: number;
    min: number;
    pat: number;
}

export interface SealedMessage {
    cipherText: Uint8Array;
    tag:        Uint8Array;
}

export class MessageCipher {

    public encryptMessage(message: Uint8Array): Promise<SealedMessage> {
        return this.sealKey.encrypt(message, {
            iv: this.sealNonce,
        }).then(result => {
            incrementNonce(this.sealNonce);
            return {
                cipherText: result.cipherText,
                tag:        result.tag
            };
        });
    }

    public decryptMessage(message: SealedMessage): Promise<Uint8Array> {
        return this.openKey.decrypt(message.cipherText, this.openNonce, message.tag).then(decrypted => {
            incrementNonce(this.openNonce);
            return decrypted;
        });
    }

    constructor(
        private sealKey: AESKey,
        private sealNonce: Uint8Array,
        private openKey: AESKey,
        private openNonce: Uint8Array
    ) {}

}

function incrementNonce(nonce: Uint8Array) {
    for (let i = nonce.byteLength - 1; i >= 0; i--) {
        if (nonce[i] < 255) {
            nonce[i]++
            return
        }
        nonce[i] = 0
    }
    throw new Error(`exhausted nonce of ${nonce.byteLength} bytes`);
}