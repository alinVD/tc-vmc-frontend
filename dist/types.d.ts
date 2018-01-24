import { Signature } from "ti-crypto";
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
    mimeType: Date;
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
export declare type DriveMap = {
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
    rows: number;
    columns: number;
}
export interface ResizeTerminalParams {
    id: number;
    rows: number;
    columns: number;
}
export interface TerminalData {
    data: Uint8Array;
}
export interface RestartVMParams {
    force: boolean;
}
export declare enum RequestType {
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
    type?: RequestType;
    payload?: Uint8Array;
}
export declare type ReplyType = "reply" | "error" | "progress" | "stream";
export interface Reply {
    type: ReplyType;
    id: number;
    payload?: any;
}
export interface Handshake {
    version: number;
    key: Uint8Array;
    sig: Signature;
    nonce: Uint8Array;
}
export interface ServerHandshake extends Handshake {
    iterations: number;
    salt: Uint8Array;
}
export interface UserHandshake extends Handshake {
    user: string;
}
