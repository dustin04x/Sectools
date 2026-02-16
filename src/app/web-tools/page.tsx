"use client";

import React, { useMemo, useState } from "react";
import { AlertTriangle, Clock3, FileCode2, Link2, ScanSearch, Send, ShieldCheck } from "lucide-react";
import { MainLayout } from "@/components/layout/main-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { copyToClipboard } from "@/lib/utils";
import { analyzeTLS, auditSecurityHeaders, extractIOCs, inspectJwt, scanSecrets } from "@/lib/api";
import { addHistoryEntry } from "@/lib/storage";

function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export default function WebToolsPage() {
  const [tab, setTab] = useState("http");

  const [httpMethod, setHttpMethod] = useState("GET");
  const [httpUrl, setHttpUrl] = useState("");
  const [httpHeaders, setHttpHeaders] = useState('{\n  "Accept": "application/json"\n}');
  const [httpBody, setHttpBody] = useState("");
  const [httpResult, setHttpResult] = useState<string>("");
  const [httpLoading, setHttpLoading] = useState(false);

  const [urlInput, setUrlInput] = useState("");
  const [urlResult, setUrlResult] = useState<Record<string, string> | null>(null);

  const [epochInput, setEpochInput] = useState("");
  const [isoInput, setIsoInput] = useState("");

  const [hashAlgorithm, setHashAlgorithm] = useState("SHA-256");
  const [hashOutput, setHashOutput] = useState("");
  const [fileName, setFileName] = useState("");

  const [iocInput, setIocInput] = useState("");
  const [iocResult, setIocResult] = useState<{
    total_iocs: number;
    counts: Record<string, number>;
    results: Record<string, string[]>;
  } | null>(null);
  const [iocLoading, setIocLoading] = useState(false);

  const [auditUrl, setAuditUrl] = useState("");
  const [auditTimeout, setAuditTimeout] = useState("10");
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditResult, setAuditResult] = useState<{
    target: string;
    final_url: string;
    status_code: number;
    score: number;
    grade: string;
    headers: Record<string, string>;
    findings: Array<{
      name: string;
      ok: boolean;
      severity: string;
      message: string;
      details?: unknown;
    }>;
  } | null>(null);

  const [jwtInput, setJwtInput] = useState("");
  const [jwtLoading, setJwtLoading] = useState(false);
  const [jwtResult, setJwtResult] = useState<{
    valid_format: boolean;
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    signature_length: number;
    findings: Array<{
      name: string;
      severity: string;
      ok: boolean;
      message: string;
      value?: number;
    }>;
    risk_score: number;
    risk_level: string;
  } | null>(null);

  const [secretInput, setSecretInput] = useState("");
  const [secretLoading, setSecretLoading] = useState(false);
  const [secretResult, setSecretResult] = useState<{
    total_findings: number;
    counts_by_type: Record<string, number>;
    counts_by_severity: Record<string, number>;
    findings: Array<{
      type: string;
      severity: string;
      preview: string;
      index: number;
    }>;
  } | null>(null);

  const [tlsTarget, setTlsTarget] = useState("");
  const [tlsPort, setTlsPort] = useState("443");
  const [tlsTimeout, setTlsTimeout] = useState("8");
  const [tlsLoading, setTlsLoading] = useState(false);
  const [tlsResult, setTlsResult] = useState<{
    target: string;
    hostname: string;
    port: number;
    tls_version: string;
    cipher: {
      name: string;
      protocol: string;
      bits: number;
    } | null;
    certificate: {
      subject: string;
      issuer: string;
      serial_number: string;
      not_before: string;
      not_after: string;
      days_remaining: number;
      san_count: number;
      san_sample: string[];
    };
    findings: Array<{
      name: string;
      ok: boolean;
      severity: string;
      message: string;
    }>;
    score: number;
    grade: string;
  } | null>(null);

  const timestampNow = useMemo(() => {
    const now = new Date();
    return {
      epoch: Math.floor(now.getTime() / 1000).toString(),
      iso: now.toISOString(),
    };
  }, []);

  const handleHttpRequest = async () => {
    if (!httpUrl.trim()) {
      toast.error("Enter a URL first.");
      return;
    }

    let parsedHeaders: Record<string, string> = {};
    try {
      parsedHeaders = httpHeaders.trim() ? JSON.parse(httpHeaders) : {};
    } catch {
      toast.error("Headers must be valid JSON.");
      return;
    }

    setHttpLoading(true);
    try {
      const response = await fetch(httpUrl, {
        method: httpMethod,
        headers: parsedHeaders,
        body: httpMethod === "GET" || httpMethod === "HEAD" ? undefined : httpBody || undefined,
      });

      const text = await response.text();
      const headers = Object.fromEntries(response.headers.entries());
      const result = JSON.stringify(
        {
          status: response.status,
          statusText: response.statusText,
          url: response.url,
          headers,
          body: text,
        },
        null,
        2
      );
      setHttpResult(result);
      addHistoryEntry({
        moduleType: "web-tools",
        inputData: { operation: "http_request", method: httpMethod, url: httpUrl },
        outputData: { status: response.status, url: response.url },
      });
      toast.success("Request complete.");
    } catch (error: any) {
      setHttpResult(JSON.stringify({ error: error?.message || "Request failed (CORS/network)." }, null, 2));
      toast.error(error?.message || "Request failed.");
    } finally {
      setHttpLoading(false);
    }
  };

  const handleParseUrl = () => {
    if (!urlInput.trim()) {
      toast.error("Enter a URL.");
      return;
    }
    try {
      const u = new URL(urlInput);
      const result = {
        href: u.href,
        protocol: u.protocol,
        host: u.host,
        hostname: u.hostname,
        port: u.port || "(default)",
        pathname: u.pathname,
        search: u.search || "(none)",
        hash: u.hash || "(none)",
        origin: u.origin,
      };
      setUrlResult(result);
      addHistoryEntry({
        moduleType: "web-tools",
        inputData: { operation: "url_parse", input: urlInput },
        outputData: result,
      });
      toast.success("URL parsed.");
    } catch {
      toast.error("Invalid URL.");
    }
  };

  const convertEpochToIso = () => {
    if (!epochInput.trim()) return;
    const value = Number(epochInput);
    if (Number.isNaN(value)) {
      toast.error("Epoch must be numeric.");
      return;
    }
    const ms = value < 1e12 ? value * 1000 : value;
    const iso = new Date(ms).toISOString();
    setIsoInput(iso);
    addHistoryEntry({
      moduleType: "web-tools",
      inputData: { operation: "epoch_to_iso", epoch: epochInput },
      outputData: { iso },
    });
  };

  const convertIsoToEpoch = () => {
    if (!isoInput.trim()) return;
    const ms = Date.parse(isoInput);
    if (Number.isNaN(ms)) {
      toast.error("Invalid ISO date.");
      return;
    }
    const epoch = Math.floor(ms / 1000).toString();
    setEpochInput(epoch);
    addHistoryEntry({
      moduleType: "web-tools",
      inputData: { operation: "iso_to_epoch", iso: isoInput },
      outputData: { epoch },
    });
  };

  const handleFileHash = async (file: File) => {
    setFileName(file.name);
    const buffer = await file.arrayBuffer();
    const digest = await crypto.subtle.digest(hashAlgorithm, buffer);
    const hex = arrayBufferToHex(digest);
    setHashOutput(hex);
    addHistoryEntry({
      moduleType: "web-tools",
      inputData: { operation: "file_hash", algorithm: hashAlgorithm, file: file.name, size: file.size },
      outputData: { hash: hex },
    });
    toast.success("File hash generated.");
  };

  const handleExtractIocs = async () => {
    if (!iocInput.trim()) {
      toast.error("Paste text to analyze first.");
      return;
    }

    setIocLoading(true);
    try {
      const result = await extractIOCs(iocInput);
      setIocResult(result);
      addHistoryEntry({
        moduleType: "web-tools",
        inputData: { operation: "ioc_extract", input_length: iocInput.length },
        outputData: { total_iocs: result.total_iocs, counts: result.counts },
      });
      toast.success("IOC extraction complete.");
    } catch (error: any) {
      toast.error(error?.message || "IOC extraction failed.");
    } finally {
      setIocLoading(false);
    }
  };

  const handleAuditHeaders = async () => {
    if (!auditUrl.trim()) {
      toast.error("Enter a URL first.");
      return;
    }

    const parsedTimeout = Number(auditTimeout);
    if (Number.isNaN(parsedTimeout) || parsedTimeout < 1 || parsedTimeout > 30) {
      toast.error("Timeout must be a number between 1 and 30 seconds.");
      return;
    }

    setAuditLoading(true);
    try {
      const result = await auditSecurityHeaders(auditUrl, parsedTimeout);
      setAuditResult(result);
      addHistoryEntry({
        moduleType: "web-tools",
        inputData: { operation: "security_headers_audit", url: auditUrl, timeout: parsedTimeout },
        outputData: {
          score: result.score,
          grade: result.grade,
          status_code: result.status_code,
          findings: result.findings.length,
        },
      });
      toast.success("Header audit complete.");
    } catch (error: any) {
      toast.error(error?.message || "Security header audit failed.");
    } finally {
      setAuditLoading(false);
    }
  };

  const handleInspectJwt = async () => {
    if (!jwtInput.trim()) {
      toast.error("Paste a JWT token first.");
      return;
    }

    setJwtLoading(true);
    try {
      const result = await inspectJwt(jwtInput.trim());
      setJwtResult(result);
      addHistoryEntry({
        moduleType: "web-tools",
        inputData: { operation: "jwt_inspect" },
        outputData: { risk_score: result.risk_score, risk_level: result.risk_level },
      });
      toast.success("JWT inspection complete.");
    } catch (error: any) {
      toast.error(error?.message || "JWT inspection failed.");
    } finally {
      setJwtLoading(false);
    }
  };

  const handleSecretScan = async () => {
    if (!secretInput.trim()) {
      toast.error("Paste text to scan first.");
      return;
    }

    setSecretLoading(true);
    try {
      const result = await scanSecrets(secretInput);
      setSecretResult(result);
      addHistoryEntry({
        moduleType: "web-tools",
        inputData: { operation: "secret_scan", input_length: secretInput.length },
        outputData: { total_findings: result.total_findings, by_severity: result.counts_by_severity },
      });
      toast.success("Secret scan complete.");
    } catch (error: any) {
      toast.error(error?.message || "Secret scan failed.");
    } finally {
      setSecretLoading(false);
    }
  };

  const handleTlsAnalyze = async () => {
    if (!tlsTarget.trim()) {
      toast.error("Enter a hostname or URL first.");
      return;
    }

    const parsedPort = Number(tlsPort);
    const parsedTimeout = Number(tlsTimeout);
    if (Number.isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      toast.error("Port must be between 1 and 65535.");
      return;
    }
    if (Number.isNaN(parsedTimeout) || parsedTimeout < 1 || parsedTimeout > 30) {
      toast.error("Timeout must be between 1 and 30.");
      return;
    }

    setTlsLoading(true);
    try {
      const result = await analyzeTLS(tlsTarget.trim(), parsedPort, parsedTimeout);
      setTlsResult(result);
      addHistoryEntry({
        moduleType: "web-tools",
        inputData: { operation: "tls_analyze", target: tlsTarget, port: parsedPort },
        outputData: { score: result.score, grade: result.grade, tls_version: result.tls_version },
      });
      toast.success("TLS analysis complete.");
    } catch (error: any) {
      toast.error(error?.message || "TLS analysis failed.");
    } finally {
      setTlsLoading(false);
    }
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Web Toolkit</h1>
          <p className="text-muted-foreground mt-1">
            Practical utility set: HTTP testing, parsing, forensics extraction, and local browser helpers.
          </p>
        </div>

        <Tabs value={tab} onValueChange={setTab} className="space-y-4">
          <TabsList className="grid w-full grid-cols-3 gap-2 lg:grid-cols-9 lg:w-[1200px]">
            <TabsTrigger value="http">HTTP Tester</TabsTrigger>
            <TabsTrigger value="url">URL Parser</TabsTrigger>
            <TabsTrigger value="time">Timestamp</TabsTrigger>
            <TabsTrigger value="hash">File Hash</TabsTrigger>
            <TabsTrigger value="ioc">IOC Extractor</TabsTrigger>
            <TabsTrigger value="headers">Header Audit</TabsTrigger>
            <TabsTrigger value="jwt">JWT Inspector</TabsTrigger>
            <TabsTrigger value="secrets">Secret Scan</TabsTrigger>
            <TabsTrigger value="tls">TLS Analyzer</TabsTrigger>
          </TabsList>

          <TabsContent value="http">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Send className="h-5 w-5" />
                  HTTP Request Tester
                </CardTitle>
                <CardDescription>Quickly test endpoints (subject to browser CORS rules).</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-4">
                  <div className="sm:col-span-1">
                    <Label>Method</Label>
                    <Select value={httpMethod} onValueChange={setHttpMethod}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"].map((m) => (
                          <SelectItem key={m} value={m}>{m}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="sm:col-span-3">
                    <Label>URL</Label>
                    <Input value={httpUrl} onChange={(e) => setHttpUrl(e.target.value)} placeholder="https://api.example.com/resource" />
                  </div>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <Label>Headers (JSON)</Label>
                    <Textarea value={httpHeaders} onChange={(e) => setHttpHeaders(e.target.value)} rows={6} className="font-mono text-xs" />
                  </div>
                  <div>
                    <Label>Body</Label>
                    <Textarea value={httpBody} onChange={(e) => setHttpBody(e.target.value)} rows={6} className="font-mono text-xs" />
                  </div>
                </div>
                <Button onClick={handleHttpRequest} disabled={httpLoading}>
                  {httpLoading ? "Sending..." : "Send Request"}
                </Button>
                {httpResult && (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label>Response</Label>
                      <Button size="sm" variant="outline" onClick={() => copyToClipboard(httpResult)}>
                        Copy
                      </Button>
                    </div>
                    <Textarea value={httpResult} readOnly rows={12} className="font-mono text-xs" />
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="url">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Link2 className="h-5 w-5" />
                  URL Parser
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-2">
                  <Input value={urlInput} onChange={(e) => setUrlInput(e.target.value)} placeholder="https://example.com:8080/path?q=1#frag" />
                  <Button onClick={handleParseUrl}>Parse</Button>
                </div>
                {urlResult && (
                  <div className="grid gap-2 sm:grid-cols-2">
                    {Object.entries(urlResult).map(([k, v]) => (
                      <div key={k} className="rounded border p-2">
                        <div className="text-xs text-muted-foreground">{k}</div>
                        <div className="font-mono text-sm break-all">{v}</div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="time">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Clock3 className="h-5 w-5" />
                  Timestamp Converter
                </CardTitle>
                <CardDescription>Convert Unix epoch and ISO 8601 timestamps both ways.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="rounded border p-3 text-sm">
                  <div>Now (epoch): <span className="font-mono">{timestampNow.epoch}</span></div>
                  <div>Now (ISO): <span className="font-mono">{timestampNow.iso}</span></div>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label>Epoch (seconds or milliseconds)</Label>
                    <Input value={epochInput} onChange={(e) => setEpochInput(e.target.value)} placeholder="1712345678" />
                    <Button variant="outline" onClick={convertEpochToIso}>Epoch -&gt; ISO</Button>
                  </div>
                  <div className="space-y-2">
                    <Label>ISO 8601</Label>
                    <Input value={isoInput} onChange={(e) => setIsoInput(e.target.value)} placeholder="2026-02-16T19:30:00.000Z" />
                    <Button variant="outline" onClick={convertIsoToEpoch}>ISO -&gt; Epoch</Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="hash">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <FileCode2 className="h-5 w-5" />
                  File Hasher
                </CardTitle>
                <CardDescription>Generate local file hash in your browser (no upload).</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-3">
                  <div className="sm:col-span-1">
                    <Label>Algorithm</Label>
                    <Select value={hashAlgorithm} onValueChange={setHashAlgorithm}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="SHA-256">SHA-256</SelectItem>
                        <SelectItem value="SHA-1">SHA-1</SelectItem>
                        <SelectItem value="SHA-512">SHA-512</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="sm:col-span-2">
                    <Label>Choose File</Label>
                    <Input
                      type="file"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) handleFileHash(file);
                      }}
                    />
                  </div>
                </div>

                {hashOutput && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">{hashAlgorithm}</Badge>
                      <Badge variant="secondary">{fileName}</Badge>
                    </div>
                    <div className="rounded border p-3 font-mono text-sm break-all">{hashOutput}</div>
                    <Button variant="outline" onClick={() => copyToClipboard(hashOutput)}>Copy Hash</Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="ioc">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <ScanSearch className="h-5 w-5" />
                  IOC Extractor
                </CardTitle>
                <CardDescription>
                  Extract common indicators from pasted logs, emails, reports, or incident notes.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Input Text</Label>
                  <Textarea
                    rows={10}
                    value={iocInput}
                    onChange={(e) => setIocInput(e.target.value)}
                    placeholder="Paste raw text containing IPs, URLs, domains, emails, hashes, CVEs..."
                    className="font-mono text-xs"
                  />
                </div>
                <div className="flex gap-2">
                  <Button onClick={handleExtractIocs} disabled={iocLoading}>
                    {iocLoading ? "Analyzing..." : "Extract IOCs"}
                  </Button>
                  {iocResult && (
                    <Button
                      variant="outline"
                      onClick={() => copyToClipboard(JSON.stringify(iocResult, null, 2))}
                    >
                      Copy JSON
                    </Button>
                  )}
                </div>

                {iocResult && (
                  <div className="space-y-3">
                    <div className="rounded border p-3">
                      <div className="text-sm">
                        Total indicators found: <span className="font-semibold">{iocResult.total_iocs}</span>
                      </div>
                    </div>
                    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                      {Object.entries(iocResult.counts).map(([type, count]) => (
                        <div key={type} className="rounded border p-3 space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="text-sm font-medium uppercase tracking-wide">{type}</div>
                            <Badge variant="outline">{count}</Badge>
                          </div>
                          <div className="max-h-40 overflow-auto space-y-1">
                            {(iocResult.results[type] || []).map((item) => (
                              <div key={item} className="rounded bg-muted px-2 py-1 font-mono text-xs break-all">
                                {item}
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="headers">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5" />
                  HTTP Security Header Audit
                </CardTitle>
                <CardDescription>
                  Analyze response headers and highlight missing or weak security controls.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-4">
                  <div className="sm:col-span-3 space-y-2">
                    <Label>Target URL</Label>
                    <Input
                      value={auditUrl}
                      onChange={(e) => setAuditUrl(e.target.value)}
                      placeholder="https://example.com"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Timeout (s)</Label>
                    <Input
                      value={auditTimeout}
                      onChange={(e) => setAuditTimeout(e.target.value)}
                      placeholder="10"
                    />
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button onClick={handleAuditHeaders} disabled={auditLoading}>
                    {auditLoading ? "Auditing..." : "Run Audit"}
                  </Button>
                  {auditResult && (
                    <Button
                      variant="outline"
                      onClick={() => copyToClipboard(JSON.stringify(auditResult, null, 2))}
                    >
                      Copy JSON
                    </Button>
                  )}
                </div>

                {auditResult && (
                  <div className="space-y-3">
                    <div className="grid gap-3 sm:grid-cols-4">
                      <div className="rounded border p-3">
                        <div className="text-xs text-muted-foreground">Final URL</div>
                        <div className="font-mono text-xs break-all">{auditResult.final_url}</div>
                      </div>
                      <div className="rounded border p-3">
                        <div className="text-xs text-muted-foreground">HTTP Status</div>
                        <div className="font-semibold">{auditResult.status_code}</div>
                      </div>
                      <div className="rounded border p-3">
                        <div className="text-xs text-muted-foreground">Score</div>
                        <div className="font-semibold">{auditResult.score}/100</div>
                      </div>
                      <div className="rounded border p-3">
                        <div className="text-xs text-muted-foreground">Grade</div>
                        <div className="font-semibold">{auditResult.grade}</div>
                      </div>
                    </div>

                    <div className="space-y-2">
                      {auditResult.findings.map((finding) => (
                        <div key={finding.name} className="rounded border p-3">
                          <div className="flex items-center justify-between">
                            <div className="font-medium">{finding.name}</div>
                            <div className="flex items-center gap-2">
                              <Badge variant={finding.ok ? "secondary" : "destructive"}>
                                {finding.ok ? "OK" : "Issue"}
                              </Badge>
                              <Badge variant="outline">{finding.severity}</Badge>
                            </div>
                          </div>
                          <div className="text-sm text-muted-foreground mt-1">{finding.message}</div>
                          {Boolean(finding.details) && (
                            <div className="mt-2 rounded bg-muted p-2 text-xs font-mono break-all">
                              {typeof finding.details === "string"
                                ? finding.details
                                : JSON.stringify(finding.details)}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="rounded border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-muted-foreground">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-600" />
                    Results are a quick baseline and do not replace full security testing.
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="jwt">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">JWT Inspector Pro</CardTitle>
                <CardDescription>
                  Decode JWT parts and flag risky claims/config patterns without verifying signature.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>JWT Token</Label>
                  <Textarea
                    rows={6}
                    value={jwtInput}
                    onChange={(e) => setJwtInput(e.target.value)}
                    placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...."
                    className="font-mono text-xs"
                  />
                </div>
                <div className="flex gap-2">
                  <Button onClick={handleInspectJwt} disabled={jwtLoading}>
                    {jwtLoading ? "Inspecting..." : "Inspect JWT"}
                  </Button>
                  {jwtResult && (
                    <Button variant="outline" onClick={() => copyToClipboard(JSON.stringify(jwtResult, null, 2))}>
                      Copy JSON
                    </Button>
                  )}
                </div>

                {jwtResult && (
                  <div className="space-y-3">
                    <div className="grid gap-3 sm:grid-cols-3">
                      <div className="rounded border p-3">
                        <div className="text-xs text-muted-foreground">Risk Score</div>
                        <div className="font-semibold">{jwtResult.risk_score}/100</div>
                      </div>
                      <div className="rounded border p-3">
                        <div className="text-xs text-muted-foreground">Risk Level</div>
                        <div className="font-semibold uppercase">{jwtResult.risk_level}</div>
                      </div>
                      <div className="rounded border p-3">
                        <div className="text-xs text-muted-foreground">Signature Length</div>
                        <div className="font-semibold">{jwtResult.signature_length}</div>
                      </div>
                    </div>

                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="space-y-2">
                        <Label>Header</Label>
                        <Textarea value={JSON.stringify(jwtResult.header, null, 2)} readOnly rows={8} className="font-mono text-xs" />
                      </div>
                      <div className="space-y-2">
                        <Label>Payload</Label>
                        <Textarea value={JSON.stringify(jwtResult.payload, null, 2)} readOnly rows={8} className="font-mono text-xs" />
                      </div>
                    </div>

                    <div className="space-y-2">
                      {jwtResult.findings.map((finding, idx) => (
                        <div key={`${finding.name}-${idx}`} className="rounded border p-3">
                          <div className="flex items-center justify-between">
                            <div className="font-medium">{finding.name}</div>
                            <div className="flex items-center gap-2">
                              <Badge variant={finding.ok ? "secondary" : "destructive"}>{finding.ok ? "OK" : "Issue"}</Badge>
                              <Badge variant="outline">{finding.severity}</Badge>
                            </div>
                          </div>
                          <div className="text-sm text-muted-foreground mt-1">{finding.message}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="secrets">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Secret Scanner</CardTitle>
                <CardDescription>
                  Detect likely leaked keys/tokens from pasted text with masked previews.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Input Text</Label>
                  <Textarea
                    rows={10}
                    value={secretInput}
                    onChange={(e) => setSecretInput(e.target.value)}
                    placeholder="Paste logs, config files, source snippets, or env blocks..."
                    className="font-mono text-xs"
                  />
                </div>
                <div className="flex gap-2">
                  <Button onClick={handleSecretScan} disabled={secretLoading}>
                    {secretLoading ? "Scanning..." : "Scan Secrets"}
                  </Button>
                  {secretResult && (
                    <Button variant="outline" onClick={() => copyToClipboard(JSON.stringify(secretResult, null, 2))}>
                      Copy JSON
                    </Button>
                  )}
                </div>

                {secretResult && (
                  <div className="space-y-3">
                    <div className="grid gap-3 sm:grid-cols-3">
                      <div className="rounded border p-3">
                        <div className="text-xs text-muted-foreground">Total Findings</div>
                        <div className="font-semibold">{secretResult.total_findings}</div>
                      </div>
                      <div className="rounded border p-3 sm:col-span-2">
                        <div className="text-xs text-muted-foreground mb-2">By Severity</div>
                        <div className="flex flex-wrap gap-2">
                          {Object.entries(secretResult.counts_by_severity).map(([sev, count]) => (
                            <Badge key={sev} variant="outline">{sev}: {count}</Badge>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="space-y-2">
                      {secretResult.findings.map((finding, idx) => (
                        <div key={`${finding.type}-${finding.index}-${idx}`} className="rounded border p-3">
                          <div className="flex items-center justify-between">
                            <div className="font-medium">{finding.type}</div>
                            <Badge variant="destructive">{finding.severity}</Badge>
                          </div>
                          <div className="text-xs text-muted-foreground mt-1">Offset: {finding.index}</div>
                          <div className="mt-2 rounded bg-muted px-2 py-1 font-mono text-xs">{finding.preview}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="tls">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">TLS Certificate Analyzer</CardTitle>
                <CardDescription>
                  Inspect certificate metadata, negotiated protocol/cipher, and expiry risk.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-6">
                  <div className="sm:col-span-3 space-y-2">
                    <Label>Target Hostname or URL</Label>
                    <Input value={tlsTarget} onChange={(e) => setTlsTarget(e.target.value)} placeholder="example.com or https://example.com" />
                  </div>
                  <div className="space-y-2">
                    <Label>Port</Label>
                    <Input value={tlsPort} onChange={(e) => setTlsPort(e.target.value)} placeholder="443" />
                  </div>
                  <div className="space-y-2">
                    <Label>Timeout (s)</Label>
                    <Input value={tlsTimeout} onChange={(e) => setTlsTimeout(e.target.value)} placeholder="8" />
                  </div>
                  <div className="flex items-end">
                    <Button className="w-full" onClick={handleTlsAnalyze} disabled={tlsLoading}>
                      {tlsLoading ? "Analyzing..." : "Analyze TLS"}
                    </Button>
                  </div>
                </div>

                {tlsResult && (
                  <div className="space-y-3">
                    <div className="grid gap-3 sm:grid-cols-4">
                      <div className="rounded border p-3">
                        <div className="text-xs text-muted-foreground">Score</div>
                        <div className="font-semibold">{tlsResult.score}/100</div>
                      </div>
                      <div className="rounded border p-3">
                        <div className="text-xs text-muted-foreground">Grade</div>
                        <div className="font-semibold">{tlsResult.grade}</div>
                      </div>
                      <div className="rounded border p-3">
                        <div className="text-xs text-muted-foreground">TLS Version</div>
                        <div className="font-semibold">{tlsResult.tls_version}</div>
                      </div>
                      <div className="rounded border p-3">
                        <div className="text-xs text-muted-foreground">Days Remaining</div>
                        <div className="font-semibold">{tlsResult.certificate.days_remaining}</div>
                      </div>
                    </div>

                    <div className="rounded border p-3 space-y-2">
                      <div className="text-sm font-medium">Certificate</div>
                      <div className="text-xs break-all"><span className="text-muted-foreground">Subject:</span> {tlsResult.certificate.subject}</div>
                      <div className="text-xs break-all"><span className="text-muted-foreground">Issuer:</span> {tlsResult.certificate.issuer}</div>
                      <div className="text-xs break-all"><span className="text-muted-foreground">Serial:</span> {tlsResult.certificate.serial_number}</div>
                      <div className="text-xs"><span className="text-muted-foreground">Valid:</span> {tlsResult.certificate.not_before} to {tlsResult.certificate.not_after}</div>
                      <div className="text-xs"><span className="text-muted-foreground">SAN count:</span> {tlsResult.certificate.san_count}</div>
                    </div>

                    <div className="space-y-2">
                      {tlsResult.findings.map((finding) => (
                        <div key={finding.name} className="rounded border p-3">
                          <div className="flex items-center justify-between">
                            <div className="font-medium">{finding.name}</div>
                            <div className="flex items-center gap-2">
                              <Badge variant={finding.ok ? "secondary" : "destructive"}>{finding.ok ? "OK" : "Issue"}</Badge>
                              <Badge variant="outline">{finding.severity}</Badge>
                            </div>
                          </div>
                          <div className="text-sm text-muted-foreground mt-1">{finding.message}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  );
}
