import { RSAKeyPair } from "ti-crypto";
import { EventEmitter } from "eventemitter3";
import { MessageCipher } from "./cipher";
import { RequestType } from "./types";
export declare enum CloseCode {
    Normal = 1000,
    GoingAway = 1001,
    ProtocolError = 1002,
    UnsupportedData = 1003,
    InvalidPayload = 1007,
    PolicyViolation = 1008,
    MessageTooBig = 1009,
    MissingExtension = 1010,
    InternalError = 1011,
    ServiceRestart = 1012,
    TryAgainLater = 1013,
    BadGateway = 1014,
}
export declare class VMConnection extends EventEmitter {
    private socket;
    private cipher;
    static PROTOCOL_VERSION: number;
    static NONCE_SIZE: number;
    private requestCounter;
    private closed;
    send(type: RequestType, payload?: any): number;
    write(streamID: number, payload: any): void;
    disconnect(code?: CloseCode, reason?: string): void;
    constructor(socket: WebSocket, cipher: MessageCipher);
}
export declare function dial(vmAddr: string, userID: string, userKey: RSAKeyPair): Promise<VMConnection>;
