import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  AlertTriangle,
  Archive,
  Database,
  Eye,
  FileDown,
  Import,
  KeyRound,
  Loader2,
  RefreshCw,
  ScanSearch,
  Trash2,
} from "lucide-react";
import { listen } from "@tauri-apps/api/event";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import * as api from "@/lib/api";
import { cn } from "@/lib/utils";
import type {
  TraeCloudDeleteInfo,
  TraeDecryptedStatus,
  TraeDeleteInfo,
  TraeImportCandidate,
  TraeImportInspect,
  TraeImportReport,
  TraeInstalledClient,
  TraeSessionDetail,
  TraeSessionInfo,
} from "@/lib/trae-types";

export default function TraeRecordsPage() {
  const [clients, setClients] = useState<TraeInstalledClient[]>([]);
  const [clientKey, setClientKey] = useState<string | null>(null);
  const [status, setStatus] = useState<TraeDecryptedStatus | null>(null);
  const [sessions, setSessions] = useState<TraeSessionInfo[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [busyLabel, setBusyLabel] = useState("");
  const [decryptProgress, setDecryptProgress] = useState<string[]>([]);
  // 归属账号筛选（会话列表）
  const [ownerFilter, setOwnerFilter] = useState("");

  // 会话详情 / 删除 对话框
  const [detail, setDetail] = useState<TraeSessionDetail | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<TraeSessionInfo | null>(null);
  const [deleteInfo, setDeleteInfo] = useState<TraeDeleteInfo | null>(null);
  const [deleteProgress, setDeleteProgress] = useState<string[]>([]);

  // 跨账号导入
  const [importTarget, setImportTarget] = useState<TraeSessionInfo | null>(null);
  const [importCandidates, setImportCandidates] = useState<TraeImportCandidate[]>([]);
  const [importHints, setImportHints] = useState<string[]>([]);
  const [importDstClient, setImportDstClient] = useState<string | null>(null);
  const [importDst, setImportDst] = useState<string | null>(null);
  const [importUid, setImportUid] = useState<string | null>(null);
  const [importInspect, setImportInspect] = useState<TraeImportInspect | null>(null);
  const [importProgress, setImportProgress] = useState<string[]>([]);
  const [importBusy, setImportBusy] = useState(false);
  const [importReport, setImportReport] = useState<TraeImportReport | null>(null);

  useEffect(() => {
    let un: (() => void) | undefined;
    void listen<{ line: string }>("trae-import-progress", (e) => {
      setImportProgress((prev) => [...prev, e.payload.line]);
    }).then((u) => {
      un = u;
    });
    return () => un?.();
  }, []);

  async function openImport(s: TraeSessionInfo) {
    if (!clientKey) return;
    setImportDstClient(clientKey);
    setImportDst(null);
    setImportUid(null);
    setImportInspect(null);
    setImportProgress([]);
    setImportReport(null);
    setImportHints([]);
    setImportTarget(s);
    try {
      const { candidates, hints } = await api.traeImportCandidates(clientKey, s.id);
      setImportCandidates(candidates);
      setImportHints(hints);
      if (candidates.length === 1) {
        void inspectDst(candidates[0]);
      }
    } catch (cause) {
      toast.error("读取可导入目标失败", { description: api.asError(cause) });
    }
  }

  async function inspectDst(c: TraeImportCandidate) {
    setImportDst(`${c.client_key}::${c.account_id}`);
    setImportUid(c.uid);
    setImportInspect(null);
    try {
      setImportInspect(await api.traeImportInspect(c.client_key, c.account_id));
    } catch (cause) {
      toast.error("目标探测失败", { description: api.asError(cause) });
    }
  }

  async function confirmImport() {
    if (!clientKey || !importTarget || !importDst || !importUid || importBusy) return;
    setImportBusy(true);
    setImportProgress([]);
    setImportReport(null);
    try {
      const res = await api.traeImportRun(clientKey, importDst.split("::")[0], importUid, [importTarget.id]);
      setImportReport(res);
      toast.success(`已导入「${importTarget.title || "（无标题）"}」`, {
        description: `目标：${res.target_label} · 复制 ${res.copied_rows} 行 · 校验会话 ${res.verified_sessions} 个 · ${res.relaunched ? "已自动重启客户端" : "客户端未自动重启"}`,
      });
    } catch (cause) {
      toast.error("导入失败", { description: api.asError(cause) });
    } finally {
      setImportBusy(false);
    }
  }

  async function loadClients() {
    try {
      const { clients } = await api.traeListClients();
      setClients(clients);
      const installed = clients.filter((c) => c.installed);
      const preferred = installed.find((c) => c.key === "trae-cn") ?? installed[0];
      setClientKey((prev) => prev ?? preferred?.key ?? null);
    } catch (cause) {
      setError(api.asError(cause));
    }
  }

  useEffect(() => {
    void loadClients();
  }, []);

  async function refresh(key: string) {
    setLoading(true);
    setError(null);
    try {
      // 有已存密钥时先重新解密（含 WAL 合并），保证列表反映 Trae 最新增删；
      // Trae 运行中手动删除的任务、新建的会话无需重启 Trae 即可同步。
      let st = await api.traeDecryptedStatus(key);
      if (st.exists) {
        try {
          const res = await api.traeDecryptWithSavedKey(key);
          st = { ...st, tables: res.report.tables };
        } catch {
          // 无已存密钥或密钥过期：沿用现有明文快照
        }
        const { sessions } = await api.traeListSessions(key);
        setSessions(sessions);
      } else {
        setSessions(null);
      }
      setStatus(st);
    } catch (cause) {
      setError(api.asError(cause));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (clientKey) void refresh(clientKey);
  }, [clientKey]);

  async function runBusy(label: string, fn: () => Promise<void>) {
    setBusy(true);
    setBusyLabel(label);
    try {
      await fn();
    } finally {
      setBusy(false);
      setBusyLabel("");
    }
  }

  async function onScanAndDecrypt() {
    if (!clientKey || busy) return;
    setDecryptProgress([]);
    await runBusy("扫描进程内存并解密", async () => {
      try {
        const res = await api.traeScanAndDecrypt(clientKey);
        setDecryptProgress(res.progress ?? []);
        const ok = res.report.hmac_ok;
        toast.success(ok ? "解密成功" : "密钥校验未通过", {
          description: `${res.report.pages} 页 · ${res.report.tables.length} 张表 · ${(res.report.elapsed_ms / 1000).toFixed(1)}s`,
        });
        await refresh(clientKey);
      } catch (cause) {
        toast.error("扫描并解密失败", { description: api.asError(cause) });
      }
    });
  }

  async function onDecryptSaved() {
    if (!clientKey || busy) return;
    await runBusy("使用已存密钥解密", async () => {
      try {
        const res = await api.traeDecryptWithSavedKey(clientKey);
        toast.success("解密成功", {
          description: `${res.report.pages} 页 · ${res.report.tables.length} 张表`,
        });
        await refresh(clientKey);
      } catch (cause) {
        toast.error("解密失败", { description: api.asError(cause) });
      }
    });
  }

  async function onExportAll() {
    if (!clientKey || busy) return;
    await runBusy("批量导出 ZIP", async () => {
      try {
        const res = await api.traeExportAll([clientKey]);
        toast.success(`已导出 ${res.ok}/${res.total} 个会话`, {
          description: res.filename,
        });
      } catch (cause) {
        toast.error("批量导出失败", { description: api.asError(cause) });
      }
    });
  }

  async function onExportSession(s: TraeSessionInfo) {
    if (!clientKey || busy) return;
    await runBusy("导出 MD", async () => {
      try {
        const res = await api.traeExportSession(clientKey, s.id);
        toast.success("已导出会话", { description: `${res.filename}（${res.size_kb} KB）` });
      } catch (cause) {
        toast.error("导出失败", { description: api.asError(cause) });
      }
    });
  }

  async function openDetail(s: TraeSessionInfo) {
    if (!clientKey) return;
    try {
      const d = await api.traeSessionDetail(clientKey, s.id);
      setDetail(d);
    } catch (cause) {
      toast.error("加载详情失败", { description: api.asError(cause) });
    }
  }

  async function openDelete(s: TraeSessionInfo) {
    if (!clientKey) return;
    setDeleteProgress([]);
    setDeleteTarget(s);
    setDeleteInfo(null);
    try {
      const info = await api.traeDeleteInfo(clientKey, s.id);
      setDeleteInfo(info);
    } catch (cause) {
      toast.error("删除预检失败", { description: api.asError(cause) });
      setDeleteTarget(null);
    }
  }

  async function confirmDelete() {
    if (!clientKey || !deleteTarget || busy) return;
    setBusy(true);
    try {
      const res = await api.traeDeleteSession(clientKey, deleteTarget.id);
      setDeleteProgress((res.progress ?? []).map((l) => String(l)));
      const cloud = res.cloud as TraeCloudDeleteInfo | undefined;
      const relaunched = res.relaunched ? " · 已自动重启客户端" : " · 客户端未自动重启";
      if (cloud?.attempted && cloud.ok === false) {
        toast.warning(`已删除本地会话「${deleteTarget.title}」`, {
          description: `云端任务列表删除失败（不影响本地结果）：${cloud.error ?? "未知原因"}${relaunched}`,
        });
      } else {
        toast.success(`已彻底删除会话「${deleteTarget.title}」`, {
          description: `实时库与解密库已同步删除，文件已移入回收站目录（可恢复）。${relaunched}`,
        });
      }
      setDeleteTarget(null);
      setDeleteInfo(null);
      await refresh(clientKey);
    } catch (cause) {
      toast.error("删除失败", { description: api.asError(cause) });
    } finally {
      setBusy(false);
    }
  }

  const selected = clients.find((c) => c.key === clientKey);
  const ownerOptions = sessions
    ? Array.from(new Set(sessions.map((s) => s.owner_label))).sort()
    : [];
  const visibleSessions = sessions?.filter(
    (s) => !ownerFilter || s.owner_label === ownerFilter,
  );

  return (
    <div className="mx-auto flex min-h-full w-full max-w-5xl flex-col gap-5 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Trae 会话记录</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            从客户端进程内存提取 SQLCipher 密钥并解密本地库 → 查看、导出 MD / ZIP、彻底删除会话（删除前自动整库备份）。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => clientKey && void refresh(clientKey)} disabled={busy}>
            <RefreshCw className="size-4" />刷新
          </Button>
          <Button size="sm" onClick={() => void onExportAll()} disabled={busy || !status?.exists || !sessions?.length}>
            <Archive className="size-4" />导出全部 ZIP
          </Button>
        </div>
      </div>

      {/* 客户端选择 */}
      {clients.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2">
          {clients.map((c) => {
            const active = c.key === clientKey;
            return (
              <button
                key={c.key}
                type="button"
                disabled={!c.installed}
                onClick={() => setClientKey(c.key)}
                className={cn(
                  "flex items-center gap-2 rounded-lg border px-3 py-2 text-sm transition-colors",
                  active
                    ? "border-foreground/20 bg-foreground/[0.06] font-medium"
                    : "border-border bg-background hover:bg-foreground/[0.03]",
                  !c.installed && "cursor-not-allowed opacity-40",
                )}
              >
                {c.label}
                {c.installed && c.has_login ? <span className="size-2 rounded-full bg-emerald-500" /> : null}
              </button>
            );
          })}
        </div>
      ) : null}

      {error ? (
        <Alert variant="destructive">
          <AlertTriangle className="size-4" />
          <AlertTitle>加载失败</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      {/* 解密状态 */}
      {loading ? (
        <Skeleton className="h-24 rounded-xl" />
      ) : status ? (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <Database className="size-4" />
              解密库状态
              {status.exists ? (
                <Badge className="bg-emerald-500/15 text-emerald-600">已解密</Badge>
              ) : (
                <Badge variant="secondary">未解密</Badge>
              )}
            </CardTitle>
            <CardDescription className="break-all font-mono text-xs">{status.path}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {status.exists ? (
              <div className="flex flex-wrap gap-1.5">
                {status.tables.map((t) => (
                  <Badge key={t.name} variant="outline">
                    {t.name}：{t.count}
                  </Badge>
                ))}
              </div>
            ) : (
              <Alert>
                <KeyRound className="size-4" />
                <AlertTitle>尚未解密</AlertTitle>
                <AlertDescription>
                  需要提取 SQLCipher 密钥。请先启动并登录 {selected?.label}，再执行一键解密。
                </AlertDescription>
              </Alert>
            )}
            <div className="flex flex-wrap items-center gap-2">
              <Button onClick={() => void onScanAndDecrypt()} disabled={busy}>
                {busy ? <Loader2 className="size-4 animate-spin" /> : <ScanSearch className="size-4" />}
                扫描密钥并解密
              </Button>
              <Button variant="outline" onClick={() => void onDecryptSaved()} disabled={busy}>
                用已存密钥解密
              </Button>
              {busy ? (
                <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <Loader2 className="size-3.5 animate-spin" />
                  {busyLabel || "处理中…"}
                </span>
              ) : null}
            </div>
            {decryptProgress.length ? (
              <pre className="max-h-40 overflow-auto rounded-lg bg-muted/60 p-3 text-xs leading-5 text-muted-foreground">
                {decryptProgress.join("\n")}
              </pre>
            ) : null}
          </CardContent>
        </Card>
      ) : null}

      {/* 会话列表 */}
      {!loading && status?.exists ? (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <CardTitle className="text-base">会话列表</CardTitle>
                <CardDescription>
                  {sessions
                    ? `共 ${sessions.length} 个会话，按最后活动倒序${
                        ownerFilter ? `；当前筛选：${ownerFilter}` : ""
                      }`
                    : "正在读取…"}
                </CardDescription>
              </div>
              {ownerOptions.length > 1 ? (
                <select
                  value={ownerFilter}
                  onChange={(e) => setOwnerFilter(e.target.value)}
                  className="h-8 rounded-md border border-border bg-background px-2 text-xs"
                >
                  <option value="">全部账号</option>
                  {ownerOptions.map((o) => (
                    <option key={o} value={o}>
                      {o}
                    </option>
                  ))}
                </select>
              ) : null}
            </div>
          </CardHeader>
          <CardContent>
            {visibleSessions && visibleSessions.length ? (
              <div className="rounded-lg border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="min-w-56">标题</TableHead>
                      <TableHead className="w-44">归属账号</TableHead>
                      <TableHead className="w-20 text-right">轮数</TableHead>
                      <TableHead className="w-40">最后活动</TableHead>
                      <TableHead className="w-40">创建时间</TableHead>
                      <TableHead className="w-44 text-right">操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {visibleSessions.map((s) => (
                      <TableRow key={s.id}>
                        <TableCell className="max-w-56">
                          <div className="truncate font-medium" title={s.title}>
                            {s.title || "（无标题）"}
                          </div>
                          <div className="font-mono text-[11px] text-muted-foreground">{s.id}</div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" title={s.owner_uid ? `uid: ${s.owner_uid}` : undefined}>
                            {s.owner_label}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{s.turns}</TableCell>
                        <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{s.updated}</TableCell>
                        <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{s.created}</TableCell>
                        <TableCell>
                          <div className="flex items-center justify-end gap-1">
                            <Button size="sm" variant="ghost" onClick={() => void openDetail(s)} title="查看详情">
                              <Eye className="size-4" />
                            </Button>
                            <Button size="sm" variant="ghost" onClick={() => void onExportSession(s)} disabled={busy} title="导出 MD">
                              <FileDown className="size-4" />
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => void openImport(s)}
                              disabled={busy}
                              title="导入到其他账号的本地库"
                            >
                              <Import className="size-4" />
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="text-destructive"
                              onClick={() => void openDelete(s)}
                              title="彻底删除（先备份）"
                            >
                              <Trash2 className="size-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                {sessions?.length
                  ? "当前筛选下没有会话记录。"
                  : "解密库中没有会话记录。"}
              </p>
            )}
          </CardContent>
        </Card>
      ) : null}

      {/* 会话详情 */}
      <Dialog open={detail !== null} onOpenChange={(v) => !v && setDetail(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="break-words">{detail?.title || "（无标题）"}</DialogTitle>
            <DialogDescription>
              <span className="font-mono text-xs">{detail?.session_id}</span>
            </DialogDescription>
          </DialogHeader>
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div className="rounded-lg bg-muted/50 p-3">
              <div className="text-xs text-muted-foreground">来源</div>
              <div className="font-medium">{detail?.source}</div>
            </div>
            <div className="rounded-lg bg-muted/50 p-3">
              <div className="text-xs text-muted-foreground">消息数</div>
              <div className="font-medium">{detail?.messages} 条</div>
            </div>
            <div className="rounded-lg bg-muted/50 p-3">
              <div className="text-xs text-muted-foreground">用户轮次</div>
              <div className="font-medium">{detail?.turns} 轮</div>
            </div>
            <div className="rounded-lg bg-muted/50 p-3">
              <div className="text-xs text-muted-foreground">时间</div>
              <div className="font-medium">{detail?.updated}</div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDetail(null)}>关闭</Button>
            {detail ? (
              <Button
                onClick={() => {
                  setDetail(null);
                  void onExportSession({
                    id: detail.session_id,
                    title: detail.title,
                    owner_uid: "",
                    owner_label: "",
                    created: "",
                    updated: "",
                    turns: 0,
                  });
                }}
              >
                <FileDown className="size-4" />导出 MD
              </Button>
            ) : null}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 彻底删除（单次确认） */}
      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(v) => {
          if (!v && !busy) {
            setDeleteTarget(null);
            setDeleteInfo(null);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="size-4" />
              彻底删除会话
            </DialogTitle>
            <DialogDescription className="break-words">
              「{deleteTarget?.title || "（无标题）"}」
            </DialogDescription>
          </DialogHeader>
          {deleteInfo ? (
            <div className="space-y-3 text-sm">
              <div className="grid grid-cols-2 gap-2">
                <div className="rounded-lg bg-muted/50 p-3">
                  <div className="text-xs text-muted-foreground">归属账号</div>
                  <div className="font-medium">{deleteInfo.owner_label || "（无归属）"}</div>
                </div>
                <div className="rounded-lg bg-muted/50 p-3">
                  <div className="text-xs text-muted-foreground">关联文件</div>
                  <div className="font-medium">{deleteInfo.files.length ? `${deleteInfo.files.length} 个（移入回收站）` : "无"}</div>
                </div>
              </div>
              <Alert>
                <Database className="size-4" />
                <AlertDescription>{deleteInfo.note}</AlertDescription>
              </Alert>
              <div className="rounded-lg border border-border p-3">
                <div className="mb-1 text-xs text-muted-foreground">云端任务列表</div>
                <div className="flex items-center gap-2">
                  {deleteInfo.cloud_credential ? (
                    <>
                      <Badge className="bg-emerald-500/15 text-emerald-600">将同步删除</Badge>
                      <span className="text-xs text-muted-foreground">
                        删除本会话在归属账号任务列表中的记录（失败时仅提示，不影响本地删除）
                      </span>
                    </>
                  ) : (
                    <>
                      <Badge variant="secondary">仅本地</Badge>
                      <span className="text-xs text-muted-foreground">
                        该归属账号无云端凭证，不尝试同步删除任务列表
                      </span>
                    </>
                  )}
                </div>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {deleteInfo.tables.map((t) => (
                  <Badge key={t.name} variant="outline">
                    {t.name}：{t.count}
                  </Badge>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" />正在预检…
            </div>
          )}
          {deleteProgress.length ? (
            <pre className="max-h-40 overflow-auto rounded-lg bg-muted/60 p-3 text-xs leading-5 text-muted-foreground">
              {deleteProgress.join("\n")}
            </pre>
          ) : null}
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)} disabled={busy}>
              取消
            </Button>
            <Button
              variant="destructive"
              disabled={!deleteInfo || busy}
              onClick={() => void confirmDelete()}
            >
              {busy ? <Loader2 className="size-4 animate-spin" /> : <Trash2 className="size-4" />}
              确认删除
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 跨账号导入 */}
      <Dialog
        open={importTarget !== null}
        onOpenChange={(v) => {
          if (!v && !importBusy) {
            setImportTarget(null);
            setImportDstClient(null);
            setImportDst(null);
            setImportInspect(null);
            setImportReport(null);
            setImportProgress([]);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Import className="size-4" />
              导入到其他账号
            </DialogTitle>
            <DialogDescription className="break-words">
              「{importTarget?.title || "（无标题）"}」→ 目标账号本地库
              <span className="block font-mono text-xs">{importTarget?.id}</span>
            </DialogDescription>
          </DialogHeader>

          {importCandidates.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              本机没有可导入账号（无已登录或留有解密库的账号）。
            </p>
          ) : (
            <div className="space-y-3 text-sm">
              {/* 目标客户端维度：仅展示所选客户端下的账号 */}
              {clients.length > 0 ? (
                <div>
                  <div className="mb-1 text-xs text-muted-foreground">目标客户端</div>
                  <div className="flex flex-wrap gap-1.5">
                    {clients
                      .filter((c) => c.installed)
                      .map((c) => {
                        const active = c.key === importDstClient;
                        return (
                          <button
                            key={c.key}
                            type="button"
                            disabled={importBusy}
                            onClick={() => {
                              setImportDstClient(c.key);
                              setImportDst(null);
                              setImportInspect(null);
                              setImportReport(null);
                            }}
                            className={cn(
                              "rounded-lg border px-2.5 py-1.5 transition-colors",
                              active
                                ? "border-foreground/20 bg-foreground/[0.06] font-medium"
                                : "border-border hover:bg-foreground/[0.03]",
                            )}
                          >
                            {c.label}
                          </button>
                        );
                      })}
                  </div>
                </div>
              ) : null}

              {(() => {
                const shown = importCandidates.filter((c) => c.client_key === importDstClient);
                if (shown.length === 0) {
                  return (
                    <p className="text-sm text-muted-foreground">
                      该客户端下没有可导入账号（需先在本机登录过或留有解密库）。
                    </p>
                  );
                }
                return (
                  <div>
                    <div className="mb-1 text-xs text-muted-foreground">选择目标账号</div>
                    <div className="flex flex-wrap gap-1.5">
                      {shown.map((c) => {
                        const key = `${c.client_key}::${c.account_id}`;
                        return (
                          <button
                            key={key}
                            type="button"
                            disabled={importBusy}
                            onClick={() => void inspectDst(c)}
                            title={
                              c.is_source
                                ? "导入到原账号 = 同库复制一份（生成新 id），原记录保留"
                                : undefined
                            }
                            className={cn(
                              "rounded-lg border px-2.5 py-1.5 transition-colors",
                              importDst === key
                                ? "border-foreground/20 bg-foreground/[0.06] font-medium"
                                : "border-border hover:bg-foreground/[0.03]",
                              !c.db_exists && "opacity-60",
                            )}
                          >
                            <span className="block">{c.label}</span>
                            <span className="block text-[11px] text-muted-foreground">
                              {c.client_label}
                              {c.is_current ? " · 当前登录" : ""}
                              {c.is_source ? " · 原账号（同库复制）" : ""}
                              {!c.db_exists ? " · 未登录过" : ""}
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                );
              })()}

              {importHints.length > 0 ? (
                <div className="space-y-1 rounded-lg bg-amber-500/10 p-3 text-xs leading-5 text-amber-700">
                  {importHints.map((h, i) => (
                    <div key={i}>{h}</div>
                  ))}
                </div>
              ) : null}

              {importInspect ? (
                <div className="flex flex-wrap gap-1.5">
                  <Badge variant={importInspect.db_exists ? "default" : "secondary"}>
                    {importInspect.db_exists ? "已有本地库" : "无本地库"}
                  </Badge>
                  <Badge variant={importInspect.key_ready ? "default" : "secondary"}>
                    密钥：{importInspect.key_ready ? "可用" : importInspect.key_source === "scan_available" ? "需扫描" : "缺失"}
                  </Badge>
                  <Badge variant={importInspect.running ? "secondary" : "outline"}>
                    {importInspect.running ? "客户端运行中（将自动退出）" : "客户端已退出"}
                  </Badge>
                  <Badge variant="outline">现有 {importInspect.sessions_now} 个会话</Badge>
                </div>
              ) : null}

              <Alert>
                <AlertTriangle className="size-4" />
                <AlertDescription className="leading-5">
                  导入会把该会话写进目标账号的本地加密库（原库先自动备份到工具目录）。写入前会自动退出目标客户端；
                  目标账号须已在本机登录过。同客户端跨账号（如 TRAE SOLO CN 的 A→B）会在库内复制会话并生成新 id，源账号记录保留。
                  与云端任务列表的同步行为未定义，若云端清理本地孤儿行，导入的会话可能被覆盖。
                </AlertDescription>
              </Alert>

              {importProgress.length ? (
                <pre className="max-h-40 overflow-auto rounded-lg bg-muted/60 p-3 text-xs leading-5 text-muted-foreground">
                  {importProgress.join("\n")}
                </pre>
              ) : null}

              {importReport ? (
                <div className="space-y-1.5 rounded-lg bg-emerald-500/10 p-3 text-xs text-emerald-700">
                  <div>复制 {importReport.copied_rows} 行（{importReport.sessions_requested} 个会话），回写 {importReport.pages} 页</div>
                  <div>新库自检会话数：{importReport.verified_sessions}</div>
                  {importReport.skipped.length ? (
                    <div>跳过（目标库已存在）：{importReport.skipped.join(", ")}</div>
                  ) : null}
                  <div className="break-all font-mono text-emerald-600/80">备份：{importReport.backup_dir}</div>
                </div>
              ) : null}
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setImportTarget(null)} disabled={importBusy}>
              取消
            </Button>
            <Button
              disabled={!importDst || !importInspect?.db_exists || importBusy}
              onClick={() => void confirmImport()}
            >
              {importBusy ? <Loader2 className="size-4 animate-spin" /> : <Import className="size-4" />}
              开始导入
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
