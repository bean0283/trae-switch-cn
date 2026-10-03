import { invoke } from "@tauri-apps/api/core";
import type { ErrorLogKind } from "./types";
import type {
  TraeAccountOverview,
  TraeBrowserInfo,
  TraeDecryptReport,
  TraeDecryptedStatus,
  TraeDeleteInfo,
  TraeExportedFile,
  TraeExportAllReport,
  TraeHandoffResult,
  TraeImportCandidate,
  TraeImportInspect,
  TraeImportReport,
  TraeImportResult,
  TraeInstalledClient,
  TraeOAuthPending,
  TraeOAuthSessionStatus,
  TraeOAuthStartResult,
  TraeScanResult,
  TraeSessionDetail,
  TraeSessionInfo,
  TraeSwitchResult,
  TraeVaultMeta,
} from "./trae-types";

/** 是否为提供桌面专属能力的 Tauri 宿主（本应用仅桌面分发）。 */
export function isWebui(): boolean {
  return typeof window !== "undefined" && !("__TAURI_INTERNALS__" in window);
}

/** Tauri mobile 也注入内部 API；用现有平台 UA 约定把桌面宿主与移动宿主区分开。 */
function isMobilePlatform(): boolean {
  if (typeof navigator === "undefined") return false;
  const ua = navigator.userAgent;
  return (
    /Android|iPhone|iPad|iPod/i.test(ua) ||
    (ua.includes("Macintosh") && navigator.maxTouchPoints > 1)
  );
}

export function isDesktop(): boolean {
  return !isWebui() && !isMobilePlatform();
}

function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(cmd, args);
}

// ---------------------------------------------------------------------------
// Trae 模块：账号切换 / 记录解密导出 / 彻底删除 / 交接记忆
// ---------------------------------------------------------------------------

/** 列出已安装的 Trae 客户端（含登录态与安装路径）。 */
export function traeListClients(): Promise<{ clients: TraeInstalledClient[] }> {
  return call("trae_list_clients");
}

/** Trae 账号总览：当前登录态 + 账号库已建档列表。 */
export function traeAccountOverview(clientKey: string): Promise<TraeAccountOverview> {
  return call("trae_account_overview", { clientKey });
}

/** 识别当前登录账号（写入账号库前调用，拿 uid 做归属）。 */
export function traeIdentifyLive(clientKey: string): Promise<Record<string, unknown>> {
  return call("trae_identify_live", { clientKey });
}

/** 把当前登录态备份进账号库（写入前自动识别 uid）。 */
export function traeBackupAccount(
  clientKey: string,
  accountId: string,
): Promise<{ ok: boolean; accountId: string; verifiedUid?: string | null; meta?: TraeVaultMeta }> {
  return call("trae_backup_account", { clientKey, accountId });
}

/** 切换到账号库中的某账号（冷切换：终止进程 → 还原载体 → 重启 → daemon 判定）。 */
export function traeSwitchTo(clientKey: string, accountId: string): Promise<TraeSwitchResult> {
  return call("trae_switch_to", { clientKey, accountId });
}

/** 回滚到某账号（本质是切回它，用于切换异常后的恢复）。 */
export function traeRollbackTo(clientKey: string, accountId: string): Promise<TraeSwitchResult> {
  return call("trae_rollback_to", { clientKey, accountId });
}

/** 从账号库删除某个账号的备份（只删本地档案，不影响客户端登录态）。 */
export function traeRemoveAccount(clientKey: string, accountId: string): Promise<{ ok: boolean }> {
  return call("trae_remove_account", { clientKey, accountId });
}

/** 重命名账号库条目（按账号名管理）。 */
export function traeRenameAccount(
  clientKey: string,
  fromId: string,
  toId: string,
): Promise<{ ok: boolean; id: string }> {
  return call("trae_rename_account", { clientKey, fromId, toId });
}

/** 导出账号备份为自包含 JSON（文件内容 base64 内联）。 */
export function traeExportAccount(
  clientKey: string,
  accountId: string,
): Promise<{ ok: boolean; id: string; payload: Record<string, unknown> }> {
  return call("trae_export_account", { clientKey, accountId });
}

/** 导入账号备份（自包含 JSON，preferName 可选覆盖账号名）。 */
export function traeImportAccount(
  clientKey: string,
  payload: Record<string, unknown>,
  preferName?: string,
): Promise<{ ok: boolean; id: string; files: number }> {
  return call("trae_import_account", {
    clientKey,
    payload,
    ...(preferName ? { preferName } : {}),
  });
}

/** 已存盘的 SQLCipher 密钥（供状态展示）。 */
export function traeSavedKey(clientKey: string): Promise<{ clientKey: string; key: string | null }> {
  return call("trae_saved_key", { clientKey });
}

/** 一键：扫描进程内存提密钥 → 校验 HMAC → 解密整库到明文 SQLite。 */
export function traeScanAndDecrypt(
  clientKey: string,
): Promise<{
  scan: TraeScanResult;
  report: TraeDecryptReport;
  decryptedDb: string;
  progress: string[];
}> {
  return call("trae_scan_and_decrypt", { clientKey });
}

/** 用已存密钥直接解密（跳过内存扫描，密钥过期会报 HMAC 失败）。 */
export function traeDecryptWithSavedKey(
  clientKey: string,
): Promise<{ report: TraeDecryptReport; decryptedDb: string }> {
  return call("trae_decrypt_with_saved_key", { clientKey });
}

/** 解密库状态（是否已生成 + 表行数概览）。 */
export function traeDecryptedStatus(clientKey: string): Promise<TraeDecryptedStatus> {
  return call("trae_decrypted_status", { clientKey });
}

/** Trae 会话列表（解密库，按最后活动倒序）。 */
export function traeListSessions(
  clientKey: string,
): Promise<{ sessions: TraeSessionInfo[] }> {
  return call("trae_list_sessions", { clientKey });
}

/** 单会话详情（标题 / 轮数 / 完整对话，供记录页预览）。 */
export function traeSessionDetail(
  clientKey: string,
  sessionId: string,
): Promise<TraeSessionDetail> {
  return call("trae_session_detail", { clientKey, sessionId });
}

/** 导出单个会话为 MD 文件（导出目录内自动去重命名）。 */
export function traeExportSession(
  clientKey: string,
  sessionId: string,
): Promise<TraeExportedFile> {
  return call("trae_export_session", { clientKey, sessionId });
}

/** 一键导出全部会话为 zip（可跨数据源）。 */
export function traeExportAll(sources: string[]): Promise<TraeExportAllReport> {
  return call("trae_export_all", { sources });
}

/** 删除预览：标题 / 各表行数 / 磁盘文件（只读，不删任何东西）。 */
export function traeDeleteInfo(clientKey: string, sessionId: string): Promise<TraeDeleteInfo> {
  return call("trae_delete_info", { clientKey, sessionId });
}

/** 彻底删除会话：整库备份 → 写实时加密库删行 → 同步删解密库 → 文件移入回收站。 */
export function traeDeleteSession(
  clientKey: string,
  sessionId: string,
): Promise<Record<string, unknown> & { progress?: string[] }> {
  return call("trae_delete_session", { clientKey, sessionId });
}

/** 账号维度导入候选：全部本机账号（vault + 解密库 local + 当前登录态），可自由切换目标。 */
export function traeImportCandidates(
  exclude: string,
  sessionId?: string,
): Promise<{ candidates: TraeImportCandidate[]; hints: string[] }> {
  return call("trae_import_candidates", { exclude, sessionId });
}

/** 目标账号导入就绪状态探测（不写库）。 */
export function traeImportInspect(
  clientKey: string,
  accountId: string,
): Promise<TraeImportInspect> {
  return call("trae_import_inspect", { clientKey, accountId });
}

/** 跨账号导入会话：源账号（已解密）→ 目标账号本地库（进度走 trae-import-progress 事件）。 */
export function traeImportRun(
  src: string,
  dst: string,
  uid: string | null,
  sessions: string[],
): Promise<TraeImportReport> {
  return call("trae_import_run", { src, dst, uid, sessions });
}

/** 交接记忆预览：解密库自动生成条目 → 组装文档，报告落点，不落盘。 */
export function traeHandoffPreview(args: {
  clientKey: string;
  projectPath?: string;
  sessionIds?: string[];
  nextSteps?: string[];
  keyFiles?: string[];
  note?: string;
}): Promise<TraeHandoffResult> {
  return call("trae_handoff_preview", args as unknown as Record<string, unknown>);
}

/** 写入交接记忆：项目工作目录 + 项目规则 + Trae 记忆库 topics 追加 + 工具目录归档。 */
export function traeHandoffWrite(args: {
  clientKey: string;
  projectPath?: string;
  sessionIds?: string[];
  nextSteps?: string[];
  keyFiles?: string[];
  note?: string;
}): Promise<TraeHandoffResult> {
  return call("trae_handoff_write", args as unknown as Record<string, unknown>);
}

// ---------------------------------------------------------------------------
// Trae 网页（OAuth）登录（trae_oauth_* 命令）
// ---------------------------------------------------------------------------

/** 发起 Trae 网页登录：起回环监听，返回授权页 URL（不自动打开浏览器）。 */
export function traeOauthStart(clientKey: string, name?: string): Promise<TraeOAuthStartResult> {
  return call("trae_oauth_start", {
    clientKey,
    ...(name ? { name } : {}),
  });
}

/**
 * 网页登录状态轮询（约 1.5s 一次）。
 * 收到回调时后端在本调用内驱动完成 token 交换并落库，返回终态。
 */
export function traeOauthStatus(): Promise<TraeOAuthSessionStatus> {
  return call("trae_oauth_status");
}

/** 停止网页登录监听（未启动时幂等）。 */
export function traeOauthStop(): Promise<{ ok: boolean }> {
  return call("trae_oauth_stop");
}

/** 查询是否有「已落盘但本进程没在监听」的登录会话（服务重启 / 弹层关闭后）。 */
export function traeOauthPending(): Promise<{ pending: TraeOAuthPending | null }> {
  return call("trae_oauth_pending");
}

/** 手动粘贴授权页回调 URL 完成登录（不依赖回环监听）。 */
export function traeOauthManual(
  clientKey: string,
  callbackUrl: string,
  name?: string,
): Promise<TraeOAuthSessionStatus> {
  return call("trae_oauth_manual", {
    clientKey,
    callbackUrl,
    ...(name ? { name } : {}),
  });
}

/** 打开授权页：默认系统浏览器，或指定浏览器的私密窗口。 */
export function traeOauthOpenUrl(
  url: string,
  privateMode?: boolean,
  browser?: string,
): Promise<{ ok: boolean; private: boolean; browser?: string; browserKey?: string }> {
  return call("trae_oauth_open_url", {
    url,
    ...(privateMode ? { private: true } : {}),
    ...(browser ? { browser } : {}),
  });
}

/** 本机可用浏览器列表（私密窗口打开用）。 */
export function traeOauthBrowsers(): Promise<{ browsers: TraeBrowserInfo[] }> {
  return call("trae_oauth_browsers");
}

// ---------------------------------------------------------------------------
// 本地登录态导入（trae_import_* 命令）
// ---------------------------------------------------------------------------

/** 导入本地登录态：解密指定客户端 storage.json 的授权条目，落库为凭证账号。 */
export function traeImportLocalLogin(clientKey: string): Promise<TraeImportResult> {
  return call("trae_import_local_login", { clientKey });
}

/** 一键导入全部已安装客户端的本地登录态。 */
export function traeImportAllLocalLogins(): Promise<{ results: TraeImportResult[] }> {
  return call("trae_import_all_local_logins");
}

// ---------------------------------------------------------------------------
// 错误日志（前端崩溃 / 未捕获错误落盘，见 lib/error-report.ts）
// ---------------------------------------------------------------------------

/** 把 Tauri command 抛出的错误统一为 Error。 */
export function asError(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return JSON.stringify(e ?? "未知错误");
}

/** 上报一条错误到本地错误日志（落盘 `~/.trae-switch-cn/error.log`）。 */
export function logError(kind: ErrorLogKind, message: string, detail?: string): Promise<void> {
  return call<unknown>("log_error", { kind, message, detail: detail ?? null }).then(
    () => undefined,
  );
}

/** 错误日志文件路径。 */
export function getErrorLogPath(): Promise<string> {
  return call<string>("get_error_log_path");
}

/** 在文件管理器中定位错误日志（日志尚未生成时由后端打开所在目录）。 */
export function revealErrorLog(): Promise<void> {
  return call<unknown>("reveal_error_log").then(() => undefined);
}
