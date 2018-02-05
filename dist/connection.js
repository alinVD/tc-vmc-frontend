"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const ti_crypto_1 = require("ti-crypto");
const eventemitter3_1 = require("eventemitter3");
const msgpack_lite_1 = require("msgpack-lite");
const cipher_1 = require("./cipher");
msgpack_lite_1.codec.preset.addExtPacker(0, Date, datePacker);
msgpack_lite_1.codec.preset.addExtUnpacker(0, dateUnpacker);
function datePacker(d) {
    return msgpack_lite_1.encode(d.getTime());
}
function dateUnpacker(buf) {
    return new Date(msgpack_lite_1.decode(buf));
}
var Protocol;
(function (Protocol) {
    Protocol[Protocol["Request"] = 0] = "Request";
    Protocol[Protocol["Reply"] = 1] = "Reply";
    Protocol[Protocol["Stream"] = 2] = "Stream";
})(Protocol || (Protocol = {}));
var CloseCode;
(function (CloseCode) {
    CloseCode[CloseCode["Normal"] = 1000] = "Normal";
    CloseCode[CloseCode["GoingAway"] = 1001] = "GoingAway";
    CloseCode[CloseCode["ProtocolError"] = 1002] = "ProtocolError";
    CloseCode[CloseCode["UnsupportedData"] = 1003] = "UnsupportedData";
    CloseCode[CloseCode["InvalidPayload"] = 1007] = "InvalidPayload";
    CloseCode[CloseCode["PolicyViolation"] = 1008] = "PolicyViolation";
    CloseCode[CloseCode["MessageTooBig"] = 1009] = "MessageTooBig";
    CloseCode[CloseCode["MissingExtension"] = 1010] = "MissingExtension";
    CloseCode[CloseCode["InternalError"] = 1011] = "InternalError";
    CloseCode[CloseCode["ServiceRestart"] = 1012] = "ServiceRestart";
    CloseCode[CloseCode["TryAgainLater"] = 1013] = "TryAgainLater";
    CloseCode[CloseCode["BadGateway"] = 1014] = "BadGateway";
})(CloseCode = exports.CloseCode || (exports.CloseCode = {}));
class VMConnection extends eventemitter3_1.EventEmitter {
    constructor(socket, cipher) {
        super();
        this.socket = socket;
        this.cipher = cipher;
        this.requestCounter = 0;
        this.closed = false;
        socket.onmessage = message => {
            let encryptedReply;
            try {
                encryptedReply = msgpack_lite_1.decode(message.data);
            }
            catch (err) {
                console.error("received bad msgpack:", message.data);
                return;
            }
            this.cipher.decryptMessage(encryptedReply).then(decrypted => {
                let lastIndex = decrypted.length - 1;
                switch (decrypted[lastIndex]) {
                    case Protocol.Reply:
                        let reply = msgpack_lite_1.decode(decrypted.subarray(0, lastIndex));
                        this.emit("reply", reply.rid, reply.payload);
                        return;
                    case Protocol.Stream:
                        let chunk = msgpack_lite_1.decode(decrypted.subarray(0, lastIndex));
                        this.emit("stream", chunk.streamID, chunk.content);
                        return;
                }
            }, err => console.log("VM connection decryption error:", err));
        };
    }
    send(type, payload) {
        if (this.closed)
            throw new Error("attempt to send message on closed VM connection");
        let req = {
            id: this.requestCounter,
            type: type,
            payload: payload || undefined
        };
        let encReq = msgpack_lite_1.encode(req);
        let toEncrypt = new Uint8Array(encReq.length + 1);
        toEncrypt.set(encReq);
        toEncrypt[toEncrypt.length - 1] = Protocol.Request;
        this.cipher.encryptMessage(toEncrypt).then(sealed => this.socket.send(msgpack_lite_1.encode(sealed).buffer), err => console.log("VM connection encryption error:", err));
        return this.requestCounter++;
    }
    write(streamID, payload) {
        if (this.closed)
            throw new Error("attempt to write to a stream on a closed VM connection");
        let chunk = {
            streamID: streamID,
            content: payload ? msgpack_lite_1.encode(payload) : undefined
        };
        let encChunk = msgpack_lite_1.encode(chunk);
        let toEncrypt = new Uint8Array(encChunk.length + 1);
        toEncrypt.set(encChunk);
        toEncrypt[toEncrypt.length - 1] = Protocol.Stream;
        this.cipher.encryptMessage(toEncrypt).then(sealed => this.socket.send(msgpack_lite_1.encode(sealed).buffer), err => console.log("VM connection encryption error:", err));
    }
    disconnect(code, reason) {
        if (this.closed)
            throw new Error("attempt to close already closed VM connection");
        if (reason && reason.length > 123)
            throw new Error("reason for closing is greater than 123 characters");
        this.socket.close(code || CloseCode.Normal, reason);
        this.closed = true;
    }
}
VMConnection.PROTOCOL_VERSION = 0;
VMConnection.NONCE_SIZE = 12;
exports.VMConnection = VMConnection;
function dial(vmAddr, userID, userKey) {
    return __awaiter(this, void 0, void 0, function* () {
        let ecPair = yield ti_crypto_1.genECDHPair("P-256", true);
        let ecPublic = yield ecPair.public.export("spki");
        let signature = yield userKey.private.sign(ecPublic);
        let nonce = new Uint8Array(VMConnection.NONCE_SIZE);
        let auth = {
            version: VMConnection.PROTOCOL_VERSION,
            key: ecPublic,
            sig: signature,
            nonce: nonce,
            user: userID
        };
        let ws = new WebSocket(vmAddr);
        ws.send(msgpack_lite_1.encode(auth));
        let server = msgpack_lite_1.decode((yield readMessage(ws)).data);
        if (server.version != VMConnection.PROTOCOL_VERSION)
            throw new Error("mismatched client/server protocol version");
        let serverPub = yield ti_crypto_1.importECDHPublic(server.key, "spki", "P-256");
        let secret = yield ecPair.private.deriveBytes(serverPub, 32);
        let keys = yield (yield ti_crypto_1.importPBKDF2Key(secret))
            .deriveBytes(64, server.iterations, "SHA-256");
        let serverKey = yield ti_crypto_1.importAESKey(keys.subarray(0, 32), "AES-GCM");
        let clientKey = yield ti_crypto_1.importAESKey(keys.subarray(32, 64), "AES-GCM");
        return new VMConnection(ws, new cipher_1.MessageCipher(clientKey, nonce, serverKey, server.nonce));
    });
}
exports.dial = dial;
function readMessage(socket) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((res, rej) => {
            socket.onmessage = message => {
                socket.onmessage = null;
                res(message);
            };
            socket.onerror = event => {
                socket.onerror = null;
                rej();
            };
        });
    });
}
