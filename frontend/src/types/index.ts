export interface User {
  id: string;
  email: string;
  ecdhPublicKey: string;
  /*
   Hex-encoded PBKDF2 salt   returned on login/register so the client can
   derive the master key without sending the raw password again. 
  */
  ecdhSalt: string;
  createdAt?: string;
}

export interface FileRecord {
  id: string;
  originalName: string;
  mimeType: string;
  size: number;
  xssScanStatus: "pending" | "clean" | "flagged";
  xssScanScore: number | null;
  createdAt: string;
  updatedAt?: string;
}

export interface SharedFile {
  shareId: string;
  file: FileRecord;
  permission: "view" | "download";
  sharedBy: string;
  fileOwner: string;
  sharedAt: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

export interface ApiError {
  message: string;
}
