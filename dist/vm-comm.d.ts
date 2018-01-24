/// <reference types="eventemitter3" />
/// <reference path="../node_modules/ti-crypto/dist/tiCrypto.d.ts" />

declare namespace vmc {
    export interface RegisterUserParams {
        userID: string;
        pubKey: Uint8Array;
    }
    export interface AllowAccessParams {
        pubKey: Uint8Array;
    }
    export interface AllowAccessReply {
    }
    export interface ListDirParams {
        driveID: string;
        id: string;
    }
    export interface Node {
        id: string;
        size: number;
        isDir: boolean;
        btime: Date;
        atime: Date;
        mtime: Date;
        ctime: Date;
        mimeType: string;
    }
    export interface CreateDirParams {
        driveID: string;
        parentID: string;
        name: string;
    }
    export interface DriveInfo {
        id: string;
        name: string;
        device: string;
        path: string;
        readonly: boolean;
    }
    export type DriveMap = {
        [driveID: string]: DriveInfo;
    };
    export interface CreateDriveParams {
        id: string;
        name: string;
        device: string;
        format: string;
        secret: Uint8Array;
    }
    export interface AttachDriveParams extends CreateDriveParams {
        readonly: boolean;
    }
    export interface DetachDriveParams {
        id: string;
    }
    export interface GiveFileParams {
        driveID: string;
        dirID: string;
        name: string;
        id: string;
        key: Uint8Array;
    }
    export interface GetFileParams {
        driveID: string;
        vmID: string;
        tcID: string;
        key: Uint8Array;
    }
    export interface DeletePathParams {
        driveID: string;
        id: string;
    }
    export interface TerminalInfo {
        id: number;
        stream: number;
        history?: Uint8Array;
        columns: number;
        rows: number;
    }
    export interface ResizeTerminalParams {
        id: number;
        columns: number;
        rows: number;
    }
    export interface TerminalData {
        data: Uint8Array;
    }
    export interface RestartVMParams {
        force: boolean;
    }
    export enum RequestType {
        ListDir = "fs:list_dir",
        CreateDir = "fs:create_dir",
        GetDrives = "fs:drives",
        CreateDrive = "fs:create_drive",
        AttachDrive = "fs:attach_drive",
        DetachDrive = "fs:detach_drive",
        GiveFile = "fs:give_file",
        GetFile = "fs:get_file",
        DeletePath = "fs:delete_path",
        AllowAccess = "fw:allow_access",
        GetHostCertificate = "fw:host_certificate",
        RegisterUser = "um:register",
        GrantUserPerms = "um:add_perms",
        RetractUserPerms = "um:retract_perms",
        GetExistingTerminals = "term:existing",
        StartTerminal = "term:start",
        ResizeTerminal = "term:resize",
        TerminalInput = "term:input",
        RestartVM = "vm:restart",
    }
    export interface Request {
        mtype: "request" | "stream";
        id: number;
        type: RequestType;
        payload?: Uint8Array;
    }
    export type ReplyType = "reply" | "error" | "progress" | "stream";
    export interface Reply {
        id: number;
        type: ReplyType;
        payload: any;
    }
    export interface Handshake {
        version: number;
        key: Uint8Array;
        sig: tiCrypto.Signature;
        nonce: Uint8Array;
    }
    export interface ServerHandshake extends Handshake {
        iterations: number;
        salt: Uint8Array;
    }
    export interface UserHandshake extends Handshake {
        user: string;
    }
    export const VERSION: Version;
    export interface Version {
        maj: number;
        min: number;
        pat: number;
    }
    export interface SealedMessage {
        cipherText: Uint8Array;
        tag: Uint8Array;
    }
    export class MessageCipher {
        private sealKey;
        private sealNonce;
        private openKey;
        private openNonce;
        encryptMessage(message: Uint8Array): Promise<SealedMessage>;
        decryptMessage(message: SealedMessage): Promise<Uint8Array>;
        constructor(sealKey: tiCrypto.AESKey, sealNonce: Uint8Array, openKey: tiCrypto.AESKey, openNonce: Uint8Array);
    }
    export enum CloseCode {
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
    export class VMConnection extends EventEmitter.EventEmitter {
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
    export function dial(vmAddr: string, userID: string, userKey: tiCrypto.RSAKeyPair): Promise<VMConnection>;
}