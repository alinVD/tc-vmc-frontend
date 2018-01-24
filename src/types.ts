import { Signature } from "ti-crypto";

/**
 * This file contains all VM controller websocket
 * interface types.
 * 
 * @author Sam Claus
 * @version 12/20/17
 * @copyright Tera Insights, LLC.
 */

// um:register
export interface RegisterUserParams {
    userID: string;
    pubKey: Uint8Array; // RSA (SPKI)
}

// fw:allow_access
export interface AllowAccessParams {
    clientCertificateDER: Uint8Array;
}

export interface AllowAccessReply {
    serverCertificateDER: Uint8Array;
    services: Map<number, Service>; // port -> service info
    password: string;
}

export interface Service {
    name: string;
    description: string;
    originalPort?: number;
    password?: string;
}

// fs:list_dir 
export interface ListDirParams {
    driveID: string;
    id:      string;
}

export interface Node {
    id:       string;
    size:     number;
    isDir:    boolean;
    btime:    Date; // created
    atime:    Date; // last opened
    mtime:    Date; // file content changed
    ctime:    Date; // file content or metadata changed
    mimeType: Date;
}

// fs:create_dir
export interface CreateDirParams {
    driveID:  string;
    parentID: string;
    name:     string;
}

export interface DriveInfo {
    id:       string; // internal ID
    name:     string;
    device:   string; // external device for drive
    path:     string; // mount point for drive
    readonly: boolean;
}

export type DriveMap = { [driveID: string]: DriveInfo };

// fs:create_drive
export interface CreateDriveParams {
    id:     string; // tiCrypt drive ID
    name:   string; // human-readable name for the drive (in request for convenience)
    device: string; // the external device as seen by the system
    format: string;
    secret: Uint8Array;
}

// fs:attach_drive
export interface AttachDriveParams extends CreateDriveParams {
    readonly: boolean; // tell the VM whether the device is readonly
}

// fs:detach_drive
export interface DetachDriveParams {
    id: string;
}

// fs:give_file
export interface GiveFileParams {
    driveID: string;
    dirID:   string;
    name:    string;
    id:      string;     // tiCrypt file ID
    key:     Uint8Array; // tiCrypt file key
}

// fs:getfile
export interface GetFileParams {
    driveID: string;
    vmID:    string; // source file ID on VM
    tcID:    string; // destination file ID in tiCrypt
    key:     Uint8Array;
}

// fs:delete_path
export interface DeletePathParams {
    driveID: string;
    id:      string;
}

export interface TerminalInfo {
    id:       number;
    stream:   number; // stream ID for I/O
    history?: Uint8Array;
    rows:     number;
    columns:  number;
}

export interface ResizeTerminalParams {
    id:      number;
    rows:    number;
    columns: number;
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
    RestartVM = "vm:restart"
}

export interface Request {
    mtype: "request"|"stream";
    id: number;
    type?: RequestType;
    payload?: Uint8Array;
}

export type ReplyType = "reply"|"error"|"progress"|"stream";

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