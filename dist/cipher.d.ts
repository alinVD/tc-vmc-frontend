import { AESKey } from "ti-crypto";
export interface SealedMessage {
    cipherText: Uint8Array;
    tag: Uint8Array;
}
export declare class MessageCipher {
    private sealKey;
    private sealNonce;
    private openKey;
    private openNonce;
    encryptMessage(message: Uint8Array): Promise<SealedMessage>;
    decryptMessage(message: SealedMessage): Promise<Uint8Array>;
    constructor(sealKey: AESKey, sealNonce: Uint8Array, openKey: AESKey, openNonce: Uint8Array);
}
