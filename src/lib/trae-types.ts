// ---------------------------------------------------------------------------
// Trae 模块：账号切换 / 记录解密导出 的类型定义（对应 src-tauri commands.rs 的 trae_* 命令）
// ---------------------------------------------------------------------------

export interface TraeInstalledClient {
  key: string;
  label: string;
  user_data_dir: string;
  installed: boolean;
  exe: string | null;
  has_login: boolean;
}

export interface TraeCarrierFile {
  rel: string;
  len: number;
}

export interface TraeVaultMeta {
  id: string;
  client: string;
  /** 账号类型：carrier（登录态载体，可切换）/ oauth（网页凭证，可合成载体后切换）。 */
  kind?: "carrier" | "oauth";
  root_dir: string;
  entries: string[];
  files: TraeCarrierFile[];
  file_count: number;
  total_bytes: number;
  created_at: string;
  last_used_at?: string | null;
  verified_uid?: string | null;
}

/** 网页（OAuth）登录得到的凭证账号内容（对应后端 oauth.json）。 */
export interface TraeOAuthAccount {
  kind: "oauth";
  id: string;
  client: string;
  displayName: string;
  uid?: string | null;
  userName?: string | null;
  avatar?: string | null;
  tokenExp?: number;
  expiredAt?: string | null;
  refreshExpiredAt?: string | null;
  deviceId?: string;
  machineId?: string;
  appVersion?: string;
  deviceSource?: string;
  host?: string;
  userRegion?: string;
  loginSource?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface TraeVaultEntry {
  id: string;
  meta: TraeVaultMeta | null;
  /** carrier（登录态载体）/ oauth（网页凭证，可合成载体后切换）。 */
  kind?: "carrier" | "oauth";
  /** kind=oauth 时的凭证详情。 */
  oauth?: TraeOAuthAccount | null;
  /** 自动获取的真实账号名（oauth displayName / 载体 storage.json username）。 */
  displayName?: string | null;
}

export interface TraeLiveAccount {
  clientKey: string;
  label: string;
  hasStorage: boolean;
  loggedIn: boolean;
  uid: string | null;
  username: string | null;
  avatarUrl: string | null;
  email: string | null;
  region: string | null;
  host: string;
  deviceId: string | null;
  machineId: string | null;
  devDeviceId: string | null;
  tokenExp: number;
  refreshExp: number;
  tokenExpText: string | null;
  refreshExpText: string | null;
  clientVersion: string | null;
  knownUids: string[];
}

export interface TraeAccountOverview {
  clientKey: string;
  loggedIn: boolean;
  running: boolean;
  live: TraeLiveAccount;
  vault: TraeVaultEntry[];
}

export type TraeSwitchOutcome = "active" | "rolled_back" | "needs_confirm";

export interface TraeSwitchResult {
  outcome: TraeSwitchOutcome;
  account_id: string;
  entries: number;
  uid: string | null;
  message: string;
  progress?: string[];
}

export interface TraeTableStat {
  name: string;
  count: number;
}

export interface TraeDecryptReport {
  out_path: string;
  pages: number;
  total_bytes: number;
  elapsed_ms: number;
  hmac_ok: boolean;
  tables: TraeTableStat[];
}

export interface TraeScanResult {
  found: boolean;
  key: string | null;
  address: string | null;
  candidates: number;
  scanned_mb: number;
  elapsed_ms: number;
  pid: number | null;
  message: string;
}

export interface TraeDecryptedStatus {
  clientKey: string;
  exists: boolean;
  path: string;
  tables: TraeTableStat[];
}

export interface TraeSessionInfo {
  id: string;
  title: string;
  created: string;
  updated: string;
  turns: number;
  /** 归属账号 uid（project.user_id；无归属为空串）。 */
  owner_uid: string;
  /** 归属账号显示名（昵称或 uid 尾号）。 */
  owner_label: string;
}

export interface TraeSessionDetail {
  session_id: string;
  title: string;
  source: string;
  turns: number;
  messages: number;
  created: string;
  updated: string;
}

export interface TraeExportMeta {
  title: string;
  turns: number;
  messages: number;
  empty_user: number;
  empty_assistant: number;
  chars: number;
}

export interface TraeExportedFile {
  session_id: string;
  filename: string;
  path: string;
  size_kb: number;
  stats: TraeExportMeta;
}

export interface TraeExportAllReport {
  path: string;
  filename: string;
  ok: number;
  failed: string[];
  total: number;
}

export interface TraeImportCandidate {
  client_key: string;
  client_label: string;
  account_id: string;
  label: string;
  display: string | null;
  uid: string;
  kind: "carrier" | "oauth" | "live" | "local";
  db_exists: boolean;
  /** 是否为该客户端当前登录账号。 */
  is_current?: boolean;
  /** 是否为本记录所属账号（同客户端同归属，导入无意义，前端禁用）。 */
  is_source?: boolean;
}

export interface TraeImportInspect {
  client_key: string;
  client_label: string;
  account_id: string;
  uid: string;
  db_exists: boolean;
  running: boolean;
  key_ready: boolean;
  key_source: "saved" | "scan_available" | "missing";
  sessions_now: number;
}

export interface TraeImportReport {
  copied_rows: number;
  sessions_requested: number;
  sessions_src: number;
  skipped: string[];
  target_client: string;
  target_label: string;
  pages: number;
  verified_sessions: number;
  backup_dir: string;
}

export interface TraeDeleteFileInfo {
  path: string;
  size_mb: number;
}

export interface TraeDeleteInfo {
  ok: boolean;
  session_id: string;
  source: string;
  title: string;
  /** 归属账号 uid（无归属为空串）。 */
  owner_uid?: string;
  /** 归属账号显示名。 */
  owner_label?: string;
  /** 该归属账号是否有云端凭证（决定是否尝试同步删除任务列表）。 */
  cloud_credential?: boolean;
  tables: TraeTableStat[];
  files: TraeDeleteFileInfo[];
  live_ok: boolean;
  note: string;
}

/** 删除结果中的云端同步状态（trae_delete_session 返回的 cloud 字段）。 */
export interface TraeCloudDeleteInfo {
  attempted?: boolean;
  ok?: boolean;
  http?: unknown;
  reason?: "no_credential" | "no_owner" | string;
  error?: string;
}

export interface TraeHandoffItem {
  sessionId?: string;
  title?: string;
  summary?: string;
  steps?: string[];
  tools?: string[];
  progress?: string;
  [key: string]: unknown;
}

export interface TraeHandoffResult {
  ok: boolean;
  clientKey: string;
  projectPath: string;
  projectName: string;
  itemCount: number;
  totalItems: number;
  markdown?: string;
  files: string[];
  skipped: string[];
  archiveDir: string;
}

// ---------------------------------------------------------------------------
// Trae 网页（OAuth）登录（对应 commands.rs 的 trae_oauth_* 命令）
// ---------------------------------------------------------------------------

export interface TraeOAuthStartResult {
  loginUrl: string;
  port: number;
  fellBack: boolean;
  deviceSource: string;
}

export interface TraeBrowserInfo {
  key: string;
  label: string;
}

export interface TraeOAuthPending {
  clientKey: string;
  name: string | null;
  loginUrl: string;
  startedAt: number;
}

/** trae_oauth_status / trae_oauth_manual 的返回（登录会话状态 + 终态结果）。 */
export interface TraeOAuthSessionStatus {
  state: string;
  message: string;
  ok?: boolean;
  account?: string | null;
  uid?: string | null;
  duplicate?: boolean;
  carrierTwin?: string | null;
  note?: string | null;
  id?: string;
  loginUrl?: string;
  port?: number;
  fellBack?: boolean;
  startedAt?: number;
  deviceSource?: string | null;
  restored?: boolean;
  pending?: TraeOAuthPending | null;
}

/** trae_import_local_login 的返回（本地登录态导入结果）。 */
export interface TraeImportResult {
  ok: boolean;
  client: string;
  id?: string;
  uid?: string | null;
  displayName?: string;
  duplicate?: boolean;
  carrierTwin?: string | null;
  source?: string;
  storageFile?: string;
  error?: string;
}
