"use client";

import React, { useState } from "react";
import { AlertTriangle, Code, Copy, Globe, Laptop, RefreshCw, Terminal } from "lucide-react";
import { MainLayout } from "@/components/layout/main-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import { generateRevShell, getLocalIPs } from "@/lib/api";
import { copyToClipboard } from "@/lib/utils";
import { addHistoryEntry } from "@/lib/storage";

const languages = [
  { value: "bash", label: "Bash", platforms: ["linux", "macos"] },
  { value: "python", label: "Python", platforms: ["linux", "windows", "macos"] },
  { value: "php", label: "PHP", platforms: ["linux", "windows", "macos"] },
  { value: "perl", label: "Perl", platforms: ["linux", "macos"] },
  { value: "ruby", label: "Ruby", platforms: ["linux", "windows", "macos"] },
  { value: "powershell", label: "PowerShell", platforms: ["windows"] },
  { value: "netcat", label: "Netcat", platforms: ["linux", "windows", "macos"] },
  { value: "ncat", label: "Ncat", platforms: ["linux", "windows", "macos"] },
];

const platforms = [
  { value: "linux", label: "Linux" },
  { value: "windows", label: "Windows" },
  { value: "macos", label: "macOS" },
];

const encodings = [
  { value: "none", label: "None" },
  { value: "base64", label: "Base64" },
  { value: "url", label: "URL Encode" },
  { value: "doubleurl", label: "Double URL Encode" },
];

export default function RevShellPage() {
  const [language, setLanguage] = useState("bash");
  const [platform, setPlatform] = useState("linux");
  const [attackerIP, setAttackerIP] = useState("");
  const [attackerPort, setAttackerPort] = useState(4444);
  const [encoding, setEncoding] = useState("none");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const availablePlatforms = languages.find((l) => l.value === language)?.platforms || [];

  const handleGenerate = async () => {
    if (!attackerIP) {
      toast.error("Please enter attacker IP");
      return;
    }

    setLoading(true);
    try {
      const response = await generateRevShell({
        language,
        platform,
        attacker_ip: attackerIP,
        attacker_port: attackerPort,
        encode: encoding === "none" ? undefined : encoding,
      });
      setResult(response);
      addHistoryEntry({
        moduleType: "rev-shell",
        inputData: {
          language,
          platform,
          attacker_ip: attackerIP,
          attacker_port: attackerPort,
          encode: encoding,
        },
        outputData: {
          payload: response.payload,
          listener_command: response.listener_command,
        },
      });
      toast.success("Payload generated");
    } catch (error: any) {
      toast.error(error.message || "Generation failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Reverse Shell Generator</h1>
          <p className="text-muted-foreground mt-1">Generate reverse shell payloads for various platforms</p>
        </div>

        <div className="flex items-center gap-3 p-4 rounded-lg border border-amber-500/50 bg-amber-500/10 text-amber-600">
          <AlertTriangle className="h-5 w-5 flex-shrink-0" />
          <div className="text-sm">
            <strong>Legal Notice:</strong> This tool is for authorized security testing only. Unauthorized access to
            computer systems is illegal. Always obtain proper permission before testing.
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Code className="h-5 w-5" />
                Configuration
              </CardTitle>
              <CardDescription>Configure payload parameters</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Language</Label>
                <Select value={language} onValueChange={setLanguage}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {languages.map((lang) => (
                      <SelectItem key={lang.value} value={lang.value}>
                        {lang.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Platform</Label>
                <Select value={platform} onValueChange={setPlatform}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {platforms.map((plat) => (
                      <SelectItem
                        key={plat.value}
                        value={plat.value}
                        disabled={!availablePlatforms.includes(plat.value)}
                      >
                        {plat.label}
                        {!availablePlatforms.includes(plat.value) && " (unsupported)"}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Attacker IP</Label>
                <div className="flex gap-2">
                  <Input
                    placeholder="Your IP address"
                    value={attackerIP}
                    onChange={(e) => setAttackerIP(e.target.value)}
                  />
                  <Button
                    variant="outline"
                    onClick={async () => {
                      try {
                        const ips = await getLocalIPs();
                        if (ips.length > 0) {
                          setAttackerIP(ips[0]);
                          toast.success(`Detected local IP: ${ips[0]}`);
                        } else {
                          toast.error("No local IP detected.");
                        }
                      } catch {
                        toast.error("Failed to detect local IP.");
                      }
                    }}
                  >
                    <Globe className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <Label>Attacker Port</Label>
                <Input
                  type="number"
                  min={1}
                  max={65535}
                  value={attackerPort}
                  onChange={(e) => setAttackerPort(parseInt(e.target.value, 10) || 4444)}
                />
              </div>

              <div className="space-y-2">
                <Label>Encoding</Label>
                <Select value={encoding} onValueChange={setEncoding}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {encodings.map((enc) => (
                      <SelectItem key={enc.value} value={enc.value}>
                        {enc.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <Button onClick={handleGenerate} disabled={loading} className="w-full">
                <RefreshCw className={cn("mr-2 h-4 w-4", loading && "animate-spin")} />
                Generate Payload
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Terminal className="h-5 w-5" />
                Generated Payload
              </CardTitle>
              <CardDescription>Copy and use on target system</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {!result ? (
                <div className="text-center py-16 text-muted-foreground">
                  <Terminal className="h-16 w-16 mx-auto mb-4 opacity-20" />
                  <p>Configure and generate a payload</p>
                  <p className="text-sm mt-1">Results will appear here</p>
                </div>
              ) : (
                <>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label>Payload</Label>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          copyToClipboard(result.payload);
                          toast.success("Copied to clipboard");
                        }}
                      >
                        <Copy className="h-4 w-4 mr-1" />
                        Copy
                      </Button>
                    </div>
                    <Textarea value={result.payload} readOnly rows={6} className="font-mono text-sm" />
                  </div>

                  {result.encoded_payload && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <Label>Encoded Payload ({result.encoding})</Label>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            copyToClipboard(result.encoded_payload);
                            toast.success("Copied to clipboard");
                          }}
                        >
                          <Copy className="h-4 w-4 mr-1" />
                          Copy
                        </Button>
                      </div>
                      <Textarea value={result.encoded_payload} readOnly rows={4} className="font-mono text-sm" />
                    </div>
                  )}

                  <div className="space-y-2">
                    <Label>Listener Commands</Label>
                    <Tabs defaultValue="netcat" className="w-full">
                      <TabsList className="grid grid-cols-3">
                        <TabsTrigger value="netcat">Netcat</TabsTrigger>
                        <TabsTrigger value="ncat">Ncat</TabsTrigger>
                        <TabsTrigger value="socat">Socat</TabsTrigger>
                      </TabsList>
                      {Object.entries(result.listener_command).map(([key, cmd]) => (
                        <TabsContent key={key} value={key}>
                          <div className="relative">
                            <code className="block p-3 rounded bg-muted font-mono text-sm">{cmd as string}</code>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="absolute right-2 top-1/2 -translate-y-1/2"
                              onClick={() => {
                                copyToClipboard(cmd as string);
                                toast.success("Copied to clipboard");
                              }}
                            >
                              <Copy className="h-4 w-4" />
                            </Button>
                          </div>
                        </TabsContent>
                      ))}
                    </Tabs>
                  </div>

                  <div className="flex flex-wrap gap-2 text-sm">
                    <Badge variant="outline">{result.language}</Badge>
                    <Badge variant="outline">{result.platform}</Badge>
                    <Badge variant="outline">
                      {result.attacker_ip}:{result.attacker_port}
                    </Badge>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Laptop className="h-5 w-5" />
              Usage Tips
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>- Start your listener before executing the payload on the target</li>
              <li>- Use common ports (80, 443, 53) to bypass firewall restrictions</li>
              <li>- Consider using encrypted channels (ncat with SSL) for stealth</li>
              <li>- URL encoding can help bypass WAF filters</li>
              <li>- Always verify you have authorization before testing</li>
            </ul>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}

function cn(...classes: (string | undefined | false)[]) {
  return classes.filter(Boolean).join(" ");
}
