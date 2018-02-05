import {
    AESKey,
    AESEncryptOptions,
    importAESKey,
    RSAKeyPair,
    genECDHPair,
    ECDHKeyPair,
    importECDHPublic,
    importPBKDF2Key,
    ECDHPublic,
    genAESKey,
    randomBytes,
    Signature
} from "ti-crypto";
import {
    EventEmitter
} from "eventemitter3";
import {
    codec as defaultCodec,
    encode,
    decode,
    createCodec,
    Decoder,
    createDecodeStream
} from "msgpack-lite";
import {
    MessageCipher,
    SealedMessage
} from "./cipher";

interface Request {
    id:       number;
    type:     string;
    payload?: Uint8Array;
}

interface Reply {
    rid:      number;
    payload?: any;
}

interface StreamChunkOut {
    streamID: number;
    content:  Uint8Array;
}

interface StreamChunkIn {
    streamID: number;
    content:  any;
}

interface Handshake {
    version: number;
    key: Uint8Array;
    sig: Signature;
    nonce: Uint8Array;
}

interface ServerHandshake extends Handshake {
    iterations: number;
    salt: Uint8Array;
}

interface UserHandshake extends Handshake {
    user: string;
}

defaultCodec.preset.addExtPacker(0, Date, datePacker);
defaultCodec.preset.addExtUnpacker(0, dateUnpacker)

function datePacker(d: Date): Buffer {
    return encode(d.getTime());
}

function dateUnpacker(buf: Uint8Array): Date {
    return new Date(decode(buf));
}

enum Protocol {
    Request = 0,
    Reply   = 1,
    Stream  = 2,
}

/**
 * Status codes for closing a websocket.
 * @see https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent#Status_codes
 */
export enum CloseCode {
    Normal = 1000,
    GoingAway,
    ProtocolError,
    UnsupportedData,
    // Skip over a few reserved codes here.
    InvalidPayload = 1007,
    PolicyViolation,
    MessageTooBig,
    MissingExtension,
    InternalError,
    ServiceRestart,
    TryAgainLater,
    BadGateway
}

export class VMConnection extends EventEmitter {

    static PROTOCOL_VERSION = 0;
    static NONCE_SIZE = 12;

    private requestCounter: number = 0;
    private closed: boolean = false;

    /**
     * Encodes and sends a request, returning the request ID.
     */
    public send(type: string, payload?: any): number {
        if (this.closed)
            throw new Error("attempt to send message on closed VM connection");

        let req: Request = {
            id: this.requestCounter,
            type: type,
            payload: payload || undefined
        };
        let encReq = encode(req);
        let toEncrypt = new Uint8Array(encReq.length + 1);
        toEncrypt.set(encReq);
        toEncrypt[toEncrypt.length - 1] = Protocol.Request;

        this.cipher.encryptMessage(toEncrypt).then(
            sealed => this.socket.send(encode(sealed).buffer),
            err => console.log("VM connection encryption error:", err)
        );

        return this.requestCounter++;
    }

    /**
     * Writes to a bidirectional stream opened VM-side.
     */
    public write(streamID: number, payload: any) {
        if (this.closed)
            throw new Error("attempt to write to a stream on a closed VM connection");
        
        let chunk: StreamChunkOut = {
            streamID: streamID,
            content: payload ? encode(payload) : undefined
        };
        let encChunk = encode(chunk);
        let toEncrypt = new Uint8Array(encChunk.length + 1);
        toEncrypt.set(encChunk);
        toEncrypt[toEncrypt.length - 1] = Protocol.Stream;

        this.cipher.encryptMessage(toEncrypt).then(
            sealed => this.socket.send(encode(sealed).buffer),
            err => console.log("VM connection encryption error:", err)
        );
    }

    /**
     * Closes the VM websocket.
     * @param code The status code for closing, defaults to CloseCode.Normal.
     * @param reason Human-readable reason for closing; max 123 characters.
     */
    public disconnect(code?: CloseCode, reason?: string) {
        if (this.closed)
            throw new Error("attempt to close already closed VM connection");
        if (reason && reason.length > 123)
            throw new Error("reason for closing is greater than 123 characters");
        this.socket.close(code || CloseCode.Normal, reason);
        this.closed = true;
    }

    constructor(
        private socket: WebSocket,
        private cipher: MessageCipher
    ) {
        super();
        socket.onmessage = message => {
            let encryptedReply: SealedMessage
            try {
                encryptedReply = decode(message.data);
            } catch(err) {
                console.error("received bad msgpack:", message.data);
                return
            }
            this.cipher.decryptMessage(encryptedReply).then(decrypted => {
                let lastIndex = decrypted.length - 1;
                switch (decrypted[lastIndex]) {
                    case Protocol.Reply:
                        let reply: Reply = decode(decrypted.subarray(0, lastIndex));
                        this.emit("reply", reply.rid, reply.payload);
                        return;
                    case Protocol.Stream:
                        let chunk: StreamChunkIn = decode(decrypted.subarray(0, lastIndex));
                        this.emit("stream", chunk.streamID, chunk.content);
                        return;
                } 
            }, err => console.log("VM connection decryption error:", err));
        };
    }

}

export async function dial(vmAddr: string, userID: string, userKey: RSAKeyPair): Promise<VMConnection> {
    let ecPair = await genECDHPair("P-256", true);
    let ecPublic = await ecPair.public.export("spki");
    let signature = await userKey.private.sign(ecPublic);
    let nonce = new Uint8Array(VMConnection.NONCE_SIZE);
    let auth: UserHandshake = {
        version: VMConnection.PROTOCOL_VERSION,
        key: ecPublic,
        sig: signature,
        nonce: nonce,
        user: userID
    };

    let ws = new WebSocket(vmAddr);
    ws.send(encode(auth));
    let server: ServerHandshake = decode((await readMessage(ws)).data);

    if (server.version != VMConnection.PROTOCOL_VERSION)
        throw new Error("mismatched client/server protocol version");

    let serverPub = await importECDHPublic(server.key, "spki", "P-256");
    let secret = await ecPair.private.deriveBytes(serverPub, 32);
    let keys = await (await importPBKDF2Key(secret))
        .deriveBytes(64, server.iterations, "SHA-256");

    let serverKey = await importAESKey(keys.subarray(0, 32), "AES-GCM");
    let clientKey = await importAESKey(keys.subarray(32, 64), "AES-GCM");

    return new VMConnection(ws, new MessageCipher(
        clientKey,
        nonce,
        serverKey,
        server.nonce
    ));
}

async function readMessage(socket: WebSocket): Promise<MessageEvent> {
    return new Promise<MessageEvent>((res, rej) => {
        socket.onmessage = message => {
            socket.onmessage = null;
            res(message);
        }
        socket.onerror = event => {
            socket.onerror = null;
            rej();
        }
    });
}