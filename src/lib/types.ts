// 与 Rust 后端命令返回结构对齐的类型定义（对照 server.py 各 API 响应）

/**
 * WorkBuddy 客户端档位：workbuddy-switch-cn 仅国内版。
 * 后端以字符串返回，历史数据与旧响应可能缺省该字段，读取时统一按国内版处理。
 */
export type WbVariant = "cn";

/**
 * 账号卡片显示名取哪个字段（每账号独立的本地偏好）。
 * 缺省/异常按 `nickname` 处理；选定字段为空时回退 `nickname → uid`。
 */
export type DisplayField = "nickname" | "phone" | "note";

export interface AccountMeta {
  id: string;
  uid: string | null;
  email: string | null;
  nickname: string | null;
  /** 官方手机号（实时读 profile_raw，仅国内版账号可能有）。 */
  phoneNumber?: string | null;
  /** 本地备注（用户自填，不来自官方数据）。 */
  note?: string | null;
  /** 本地显示字段偏好。 */
  displayField?: DisplayField | null;
  enterpriseName: string | null;
  expiresAt: number | null;
  refreshExpiresAt: number | null;
  refreshedAt: number | null;
  createdAt: number | null;
  needsRelogin: boolean;
  needsReloginReason: string | null;
  /** 账号所属档位；缺省（旧后端/历史账号）按国内版处理。 */
  variant?: WbVariant;
}

export interface AppStatus {
  running: boolean;
  authFile: string;
  current: {
    uid: string | null;
    nickname: string | null;
    email: string | null;
  } | null;
  appPath: string;
  version: string;
  /** 上述字段所属档位；缺省按国内版处理。 */
  variant?: WbVariant;
}

export interface OAuthStartResult {
  loginId: string;
  verificationUri: string;
  expiresIn: number;
}

export interface OAuthPollResult {
  done: boolean;
  result?: AccountMeta;
  error?: string;
}

/** 导出文件中的完整账号记录（含 token，仅导出命令返回；字段与账号库原始记录一致）。 */
export interface AccountRecord {
  id?: string;
  uid?: string | null;
  nickname?: string | null;
  email?: string | null;
  access_token?: string | null;
  refresh_token?: string | null;
  token_type?: string | null;
  domain?: string | null;
  expiresAt?: number | null;
  refreshExpiresAt?: number | null;
  auth_raw?: unknown;
  profile_raw?: unknown;
  createdAt?: number | null;
  [key: string]: unknown;
}

/** 导入文件账号的脱敏预览（不含 token）。 */
export interface ImportPreviewAccount {
  index: number;
  uid: string | null;
  nickname: string | null;
  email: string | null;
  hasToken: boolean;
  /** access_token 为 WorkBuddy 加密信封：可导入，但仅切换可用（签到/积分不可用）。 */
  encrypted: boolean;
}

/** 导入结果计数。 */
export interface ImportResult {
  ok: boolean;
  imported: number;
  skipped: number;
  overwritten: number;
}

export interface Session {
  id: string;
  title: string;
  cwd: string;
  updatedAt: number;
  hasHistory: boolean;
  /** WorkBuddy playground（侧栏「任务」）；缺省视为空间会话。 */
  isPlayground?: boolean;
}

/** 临时备份的清理状态：cleaned 已回收；pending 已保留待下次维护重试；legacyRetained 旧操作无生命周期记录。 */
export type SessionBackupCleanupState = "cleaned" | "pending" | "legacyRetained";

/**
 * 临时备份残留（待清理 / 待恢复）：复制、同步、恢复报告共用同一结构。
 * `cleanupPending` 表示已完成但本轮没清理成功（下次切号重试）；`needsRecovery`
 * 表示必须保留材料、需要恢复流程或人工确认。
 */
export interface TemporaryFileInfo {
  operationId: string;
  sessionId?: string;
  title?: string;
  state: "cleanupPending" | "needsRecovery";
  reason: string;
}

/** 本次新建的副本（目标 UUID 由后端预分配）。 */
export interface CopyResult {
  id: string;
  newId: string;
  groupId: string;
  /** 待清理位置（已清理为 null）；仅表示待清理，不是可撤销备份。 */
  backup: string | null;
  /** 成功后立即清理：cleaned 已回收 / pending 待下次维护重试；旧后端可能缺字段。 */
  cleanupState?: SessionBackupCleanupState;
  /** 清理失败原因（`cleanupState` 为 pending 时有值）。 */
  cleanupError?: string;
}

/** 目标账号上已有真实有效的副本：复用而不是重复复制。 */
export interface LinkedCopyResult {
  id: string;
  sessionId: string;
  groupId: string;
}

/** 切换时的会话复制报告；复制失败时后端只回 `error`（切换本身仍继续）。 */
export interface SessionCopyReport {
  sourceUid?: string;
  targetUid?: string;
  /** 跨档复制时带两侧档位；同档复制不出现这两个字段。 */
  sourceVariant?: WbVariant;
  targetVariant?: WbVariant;
  copied?: CopyResult[];
  alreadyLinked?: LinkedCopyResult[];
  errors?: { id: string; error: string }[];
  /** 仍有未完成的会话写入时为 true（失败项可重试，不会产生第二个副本）。 */
  needsRecovery?: boolean;
  /** 临时备份残留（待清理/待恢复）；无异常时为空数组。 */
  temporaryFiles?: TemporaryFileInfo[];
  error?: string;
}

/** 切换前对未完成会话写入的恢复结果。 */
export interface SessionRecoveryReport {
  recovered: number;
  abandoned: number;
  needsRecovery: { operationId: string; reason: string; retryable: boolean }[];
  /** 临时备份残留（待清理/待恢复）；无异常时为空数组。 */
  temporaryFiles?: TemporaryFileInfo[];
}

// ---------------------------------------------------------------------------
// 会话同步（关联组）：预览与执行契约，与 core / Tauri / HTTP 三端同形
// ---------------------------------------------------------------------------

/**
 * 同步判定结果（design §3.2 优先级表）：
 * `identical` 两边一致、`fastForward` 有新增可同步、`ahead` 仅目标账号有更新、
 * `diverge` 两边都改过需显式覆盖、`unknown` 无法确认。
 */
export type SessionSyncVerdict = "identical" | "fastForward" | "ahead" | "diverge" | "unknown";

/** 同步写入模式：只有后端 `availableModes` 里给出的模式才允许提交。 */
export type SessionSyncMode = "fastForward" | "overwrite" | "unifyOverwrite";

/** 关联组成员（不含正文）：`state` 为 active 时才算该账号的有效成员。 */
export interface SessionLinkMember {
  memberId: string;
  uid: string;
  accountId: string | null;
  sessionId: string;
  state: "active" | "stale" | "superseded";
}

/** 关联组的预览项；`defaultChecked` 与 `availableModes` 是勾选权限的唯一来源。 */
export interface SessionLinkPreviewGroup {
  groupId: string;
  title: string;
  cwd: string;
  verdict: SessionSyncVerdict;
  /** 来源独有记录数（多重集差集，仅用于向用户解释）。 */
  extraA: number;
  /** 目标独有记录数（多重集差集，仅用于向用户解释）。 */
  extraB: number;
  common: number;
  defaultChecked: boolean;
  /** 为空表示该项不可勾选（identical / ahead / unknown / 预览凭据不可用）。 */
  availableModes: SessionSyncMode[];
  reason: string;
  /** 记录数（不是消息数）：不可验证时 source/target 为 0、baseline 为 null。 */
  recordCount: { source: number; target: number; baseline: number | null };
  source: SessionLinkMember | null;
  target: SessionLinkMember | null;
  /** 勾选时必须原样回传的预览凭据；缺失即不可勾选。 */
  previewToken?: string;
}

/** 关联会话预览：`supported` 为 false（或 storeStatus 为 unsupported）时不展示同步区块。 */
export interface SessionLinksPreview {
  supported: boolean;
  storeStatus: "ready" | "missing" | "unavailable" | "unsupported";
  storeError?: string;
  sourceUid: string;
  targetUid: string;
  /** 跨档预览时带两侧档位；同档预览不出现这两个字段。 */
  sourceVariant?: WbVariant;
  targetVariant?: WbVariant;
  groups: SessionLinkPreviewGroup[];
}

/** 一条同步选择：与预览凭据绑定，执行时后端会重新校验。 */
export interface SessionSyncSelection {
  groupId: string;
  previewToken: string;
  mode: SessionSyncMode;
}

/** 已同步的关联组（保留目标 sessionId 与标题）。 */
export interface SessionSyncResultItem {
  groupId: string;
  status: "synced";
  verdict: SessionSyncVerdict;
  mode: SessionSyncMode;
  sourceSessionId: string;
  targetSessionId: string;
  recordCount: { source: number; targetBefore: number; target: number };
  updatedAt: number;
  /** 待清理位置（已清理为 null）；旧操作可能仍返回目录路径。 */
  backup: string | null;
  backupManifest: string | null;
  /** 成功后立即清理：cleaned 表示临时备份已回收；pending 表示待下次维护重试。 */
  cleanupState?: SessionBackupCleanupState;
  cleanupError?: string;
  message: string;
}

/** 被跳过的关联组：`reasonCode` 为 previewStale 时说明预览已过期，不得显示为成功。 */
export interface SessionSyncSkippedItem {
  groupId: string;
  status: "skipped";
  reasonCode: string;
  message: string;
  verdict: SessionSyncVerdict | null;
}

/** 同步执行报告；`errors` 里可能是整批被拒（无 groupId）。 */
export interface SessionSyncReport {
  synced: SessionSyncResultItem[];
  skipped: SessionSyncSkippedItem[];
  errors: { groupId?: string; error: string }[];
  /** 仍有未完成/无法安全恢复的会话写入时为 true。 */
  needsRecovery?: boolean;
  /** 临时备份残留（待清理/待恢复）；无异常时为空数组。 */
  temporaryFiles?: TemporaryFileInfo[];
}

// ---------------------------------------------------------------------------
// Client-scoped session group directory
// ---------------------------------------------------------------------------

export type SessionGroupClient = "workbuddy";
export type SessionGroupStatus = "latest" | "behind" | "diverge" | "missing" | "unknown";
export type SessionMemberVersionStatus = SessionGroupStatus | "stale" | "superseded";

export interface SessionGroupSummary {
  key: string;
  client: SessionGroupClient;
  variantScope: WbVariant | null;
  groupId: string;
  groupVariant: WbVariant;
  title: string;
  projectLabel: string;
  latestActivityAt: number;
  memberCount: number;
  activeMemberCount: number;
  accountNames: string[];
  summaryStatus: SessionGroupStatus;
  summaryText: string;
  safeSourceMemberId: string | null;
  hasSafeSource: boolean;
}

export interface SessionGroupMemberDetail {
  memberId: string;
  accountId: string | null;
  uid: string;
  sessionId: string;
  accountName: string;
  variant: WbVariant;
  linkState: "active" | "stale" | "superseded";
  versionStatus: SessionMemberVersionStatus;
  title: string;
  projectLabel: string;
  updatedAt: number;
  recordCount: number | null;
  contentPreview?: { speaker: string; text: string }[];
  contentState: "ready" | "missing" | "unavailable";
  reason: string;
  canBeSource: boolean;
}

export interface SessionGroupList {
  client: SessionGroupClient;
  variantScope: WbVariant | null;
  storeStatus: "missing" | "ready" | "unavailable";
  storeError?: string;
  groups: SessionGroupSummary[];
}

export interface SessionGroupDetail extends SessionGroupSummary {
  members: SessionGroupMemberDetail[];
  addTargets: AccountMeta[];
  divergence?: {
    commonMemberIds: string[];
    branches: string[][];
  };
}

export interface SessionGroupPairPreview {
  client: SessionGroupClient;
  variantScope: WbVariant | null;
  groupId: string;
  sourceMemberId: string;
  targetMemberId: string;
  verdict: SessionSyncVerdict;
  availableModes: SessionSyncMode[];
  previewToken: string | null;
  reason: string;
  recordCount: { source: number; target: number; baseline: number | null } | null;
  extraTargetCount: number;
}

/** One read-only plan for making every active copy match a chosen group member. */
export interface SessionGroupUnifyPlan {
  client: SessionGroupClient;
  groupId: string;
  sourceMemberId: string;
  sourceName: string;
  targets: {
    memberId: string;
    accountName: string;
    preview: SessionGroupPairPreview | null;
    error: string | null;
  }[];
}

/** A client-reported current login, matched by stable UID or saved account ID. */
export interface SessionGroupCurrentAccount {
  variant?: WbVariant;
  uid?: string | null;
  accountId?: string | null;
  running?: boolean;
}

export interface SessionGroupActionReport {
  client: SessionGroupClient;
  groupId: string;
  sourceMemberId?: string;
  targetMemberId?: string;
  synced: SessionSyncResultItem[];
  skipped: SessionSyncSkippedItem[];
  errors: { groupId?: string; error: string }[];
  needsRecovery?: boolean;
  temporaryFiles?: TemporaryFileInfo[];
  restartedVariants?: WbVariant[];
  /** 插件侧：本次由 wb-switch 关闭并成功重开了 VS Code。 */
  restartedEditor?: boolean;
  /** 插件侧：写入已完成但 VS Code 未能自动重新打开（无 `errors` 数组的入口用它兜底）。 */
  editorError?: string;
}

/**
 * 应用内通知存档条目：toast 只存活几秒，这里保存最近 100 条供事后回看
 * （支持排障与验收核对，例如切号成功后到底提示了什么）。
 */
export interface AppNotification {
  level: "success" | "error" | "warning" | "info";
  title: string;
  description?: string;
  /** 毫秒时间戳。 */
  at: number;
}

/** 记忆交接：单条会话级条目（预览 / 归档共用）。 */
export interface HandoffItem {
  sessionId: string;
  title: string;
  time: string;
  intent: string;
  actions: string[];
  outcome: string;
  learned: string[];
  projectPath?: string | null;
}

/** 记忆交接预览结果（`handoff_preview`，不落盘）。 */
export interface HandoffPreviewResult {
  ok: boolean;
  projectPath: string;
  projectName: string;
  itemCount: number;
  totalItems: number;
  /** 交接文档 Markdown 全文。 */
  markdown: string;
  /** 预览时计划写入的文件（绝对路径）。 */
  files: string[];
  /** 预览时被跳过的落点及原因。 */
  skipped: string[];
  archiveDir: string;
}

/** 记忆交接写入结果（`handoff_write`）。 */
export interface HandoffWriteResult {
  ok: boolean;
  projectPath: string;
  projectName: string;
  itemCount: number;
  totalItems: number;
  /** 实际写入的文件（绝对路径）。 */
  files: string[];
  /** 写入失败的落点及原因。 */
  skipped: string[];
  archiveDir: string;
}


/**
 * 错误日志来源（`~/.wb-switch/error.log` 的 `kind` 字段）：
 * 渲染崩溃 / 未捕获异常或 Promise 拒绝 / 后端错误。
 */
export type ErrorLogKind = "frontend_crash" | "frontend_unhandled" | "backend";

export interface SwitchResult {
  ok: boolean;
  account: string;
  /** 目标账号自身档位；缺省按国内版处理。 */
  variant?: WbVariant;
  backup: string | null;
  sessionCopy?: SessionCopyReport;
  /** 本次的会话同步报告（未勾选同步时不返回）；含跳过与失败原因，不只是成功数。 */
  sessionSync?: SessionSyncReport;
  sessionRecovery?: SessionRecoveryReport;
}

export interface CheckinConfig {
  enabled: boolean;
  /** 关闭自动签到的账号 id；状态展示和刷新附带签到也跳过，主动手动签到不受影响。 */
  excluded_account_ids?: string[];
  /** 签到时间段（"HH:MM"，本地时区）；空串 = 不限制。两端都合法且 start < end 才生效。 */
  checkin_start: string;
  checkin_end: string;
  /** Legacy persisted fields; accepted by the backend but ignored by scheduling. */
  start_hour?: number;
  end_hour?: number;
  keepalive_days: number;
  lazy_refresh_hours: number;
}

export interface CheckinLog {
  ts: number;
  accountId: string | null;
  email: string;
  result: string;
  error?: string;
  /** 该行所属档位；历史日志缺省按国内版处理。 */
  variant?: WbVariant;
}

export interface CheckinResult {
  result: string;
  error?: string;
  /** 国际版签到活动未开放时的业务判定；不写成功日志、不计入失败重试。 */
  inactive?: boolean;
}

export interface TravelConfig {
  enabled: boolean;
}

export type TravelStatusLabel = "untraveled" | "no-buddy" | "traveling" | "finished";

export interface TravelStatus {
  label: TravelStatusLabel;
  rewardCredit: number | null;
  locationName?: string | null;
  arriveAt?: number | null;
}

/** 单个受限模型；`model` 为 null 表示日志里归因不到模型（显示「未知模型」，不猜测）。 */
export interface RateLimitEntry {
  model: string | null;
  /** 官方日志原文给出的恢复时刻（毫秒）。 */
  resetAt: number;
  /** 该事件首次出现的时刻（毫秒）。 */
  firstSeenAt: number;
  /** 去重前的原始命中行数（调试/排查用）。 */
  hitCount: number;
}

/** 一个账号当前受限的全部模型（按 `resetAt` 升序）。 */
export interface AccountRateLimits {
  accountId: string;
  limited: RateLimitEntry[];
}

/** 模型限额台账：一次返回全部账号的当前受限状态（数据来自本机日志）。 */
export interface RateLimitsPayload {
  scannedAt: number;
  /** 固定 2 天，回显便于调试。 */
  windowDays: number;
  /** 只包含至少有一个受限模型的账号。 */
  accounts: AccountRateLimits[];
}

/** 一处客户端 hook 配置的安装状态。 */
export interface RateLimitHookTarget {
  /** 备份标签（workbuddy）。 */
  label: string;
  /** `settings.json` 路径。 */
  path: string;
  /** 该客户端数据根目录是否存在（唯一的存在性判据；不存在则不参与安装）。 */
  exists: boolean;
  /** 该配置里是否已注册本工具的 Stop / FinalStop。 */
  installed: boolean;
}

/**
 * 限额 hook 安装状态：脚本 + 三处客户端配置逐项结果。
 *
 * `installed` = 脚本存在且至少一处配置注册成功；`lastEventAt` 是最近一次由后端
 * 入账的 hook 限额事件时刻（null = 从未收到）。
 */
export interface RateLimitHookStatus {
  scriptPath: string;
  scriptExists: boolean;
  eventsPath: string;
  installed: boolean;
  lastEventAt?: number | null;
  targets: RateLimitHookTarget[];
}

/** 限额监听开关（`~/.wb-switch/rate_limit_config.json`）。 */
export interface RateLimitConfig {
  enabled: boolean;
  /** 用户点过「卸载 hook」→ 启动时不再自动接入；重新点「接入 hook」清除。 */
  hookOptOut: boolean;
  /**
   * 是否扫描 WorkBuddy 的运行日志以兜底识别限额事件（默认 true）。
   * 429 不触发 hook 事件时日志是兜底数据源；关闭后仅依赖 hook 实时上报。
   */
  scanIdeLogs: boolean;
}

export interface CreditResource {
  packageCode: string | null;
  packageName: string | null;
  total: number;
  remaining: number;
  used: number;
  status: number | null;
  expireAt: number | null;
  expired: boolean;
  expiringSoon: boolean;
}

export interface CreditExpiry {
  ok: boolean;
  accountId?: string | null;
  accountName?: string;
  updatedAt?: number;
  totalCapacity?: number;
  totalRemaining?: number;
  expiringSoonRemaining?: number;
  expiredRemaining?: number;
  soonestExpireAt?: number | null;
  expiringSoon?: boolean;
  expired?: boolean;
  resources?: CreditResource[];
  error?: string;
}

export interface CreditStatsSummary {
  currentRemaining: number;
  currentCapacity: number;
  usageToday: number;
  usage7Days: number;
  usageThisMonth: number;
  todayCheckedInAccounts: number;
  todaySuccess: number;
  todayAlready: number;
  todayFailed: number;
}

export interface CreditStatsDailyPoint {
  date: string;
  usage: number;
  /** 官方用量按模型聚合（全量，不受请求明细条数限制）；本地观察口径下为空 */
  models?: { model: string; requestCount: number; credit: number }[];
}

export interface CreditStatsAccount {
  accountId: string;
  accountName: string;
  isCurrent: boolean;
  currentRemaining: number | null;
  totalCapacity: number | null;
  lastSnapshotAt: number | null;
  usageToday: number;
  usage7Days: number;
  usageThisMonth: number;
  checkedInToday: boolean | null;
  checkinStatusToday: string | null;
  lastCheckinAt: number | null;
  lastCheckinResult: string | null;
  /** 按账号的逐日观察消耗（缺省兼容旧后端）；官方可用时趋势图优先使用官方 daily */
  daily?: CreditStatsDailyPoint[];
  /** 档位标记。后端当前不下发，前端容忍性读取；缺省时回退到按 accountId 的映射表 */
  variant?: WbVariant;
}

export interface CreditStatsUsageEvent {
  kind: "usage";
  ts: number;
  date: string;
  accountId: string;
  accountName: string;
  amount: number;
  /** 档位标记。后端当前不下发，前端容忍性读取；缺省时回退到按 accountId 的映射表 */
  variant?: WbVariant;
}

export interface CreditStatsCheckinEvent {
  kind: "checkin";
  ts: number;
  date: string;
  accountId: string | null;
  accountName: string;
  result: string;
  error?: string | null;
  /** 档位标记。后端当前不下发，前端容忍性读取；缺省时回退到按 accountId 的映射表 */
  variant?: WbVariant;
}

export type CreditStatsEvent = CreditStatsUsageEvent | CreditStatsCheckinEvent;

export type CreditOfficialUsageStatus = "complete" | "partial" | "unavailable";

export interface CreditOfficialUsageSummary {
  usageToday: number;
  usage7Days: number;
  usageThisMonth: number;
}

export interface CreditOfficialUsageModel {
  model: string;
  requestCount: number;
  credit: number;
}

export interface CreditOfficialUsageAccount {
  accountId: string;
  accountName: string;
  ok: boolean;
  requestCount: number;
  detailTruncated: boolean;
  usageToday: number | null;
  usage7Days: number | null;
  usageThisMonth: number | null;
  error?: string | null;
  reportedTotal?: number | null;
  fetchedCount?: number;
  /** 缺省兼容旧后端响应。 */
  models?: CreditOfficialUsageModel[];
  /** 按账号的逐日官方消耗（全量聚合，不受 requests 明细上限影响；缺省兼容旧后端） */
  daily?: CreditStatsDailyPoint[];
}

export interface CreditOfficialUsageRequest {
  accountId: string;
  accountName: string;
  requestId: string;
  credit: number;
  model: string;
  client: string;
  requestTime: string;
}

export interface CreditOfficialUsageError {
  accountId: string;
  accountName: string;
  error: string;
}

export interface CreditOfficialUsage {
  status: CreditOfficialUsageStatus;
  rangeStart: string;
  rangeEnd: string;
  /** 官方用量最近一次采集时间；缓存命中时保持采集当时的时间。 */
  collectedAt?: number;
  summary: CreditOfficialUsageSummary;
  daily: CreditStatsDailyPoint[];
  accounts: CreditOfficialUsageAccount[];
  requests: CreditOfficialUsageRequest[];
  /** 官方全部有效请求按模型汇总；不受 requests 明细上限影响。 */
  models?: CreditOfficialUsageModel[];
  detailLimitPerAccount: number;
  errors: CreditOfficialUsageError[];
}

export interface CreditStatistics {
  generatedAt: number;
  retentionDays: number;
  coverageStartAt: number | null;
  summary: CreditStatsSummary;
  daily: CreditStatsDailyPoint[];
  accounts: CreditStatsAccount[];
  events: CreditStatsEvent[];
  /** 官方接口不可用时仍使用上述本地观察字段；缺省兼容旧后端。 */
  officialUsage?: CreditOfficialUsage;
}

export interface TokenStatsTotals { total: number; input: number; output: number; cacheRead: number; cacheWrite: number; uncachedInput: number; records: number; cacheHitRate: number | null; }
export interface TokenStatsGroup extends TokenStatsTotals { key: string; title?: string | null; project?: string; sessionId?: string; }
/** 一次模型调用的明细行；`total = input + output + cacheWrite`，`uncachedInput = max(0, input - cacheRead)`，`thinking` 是 `output` 中思考过程的 token 数（回复内容 = max(0, output - thinking)），均与聚合口径一致。 */
export interface TokenStatsRequestRow { timestamp: number; model: string; project: string; sessionId: string; title?: string | null; input: number; output: number; cacheRead: number; cacheWrite: number; uncachedInput: number; thinking: number; total: number; }
/** WorkBuddy 本地数据源统计。 */
export interface TokenStatsSource { source: "workbuddy"; summary: TokenStatsTotals; models: TokenStatsGroup[]; projects: TokenStatsGroup[]; sessions: TokenStatsGroup[]; daily: TokenStatsGroup[]; /** Optional model-specific daily series for trend filtering. */ dailyByModel?: Record<string, TokenStatsGroup[]>; requests?: TokenStatsRequestRow[]; hours: TokenStatsGroup[]; filesScanned: number; parseErrors: number; coverageStartAt?: number | null; coverageEndAt?: number | null; }
export interface TokenStatistics { generatedAt: number; rangeDays?: number | null; sources: TokenStatsSource[]; }
