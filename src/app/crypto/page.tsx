"use client";

import React, { useMemo, useState } from "react";
import { Copy, Hash, KeyRound, Lock, RefreshCw, ShieldCheck, Unlock } from "lucide-react";
import { MainLayout } from "@/components/layout/main-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import {
  decodeJwt,
  decryptData,
  encryptData,
  generateHmac,
  generatePassword,
  generateRsaKeypair,
  hashData,
} from "@/lib/api";
import { cn, copyToClipboard } from "@/lib/utils";
import { addHistoryEntry } from "@/lib/storage";

const cipherAlgorithms = ["AES-256", "RSA", "Base64", "URL", "Hex", "ROT13"];
const hashAlgorithms = ["SHA-256", "SHA-512", "SHA3-256", "SHA3-512", "BLAKE2b", "MD5", "SHA-1", "bcrypt"];
const hmacAlgorithms = ["SHA-256", "SHA-512", "SHA3-256", "SHA3-512", "BLAKE2b", "MD5", "SHA-1"];

export default function CryptoPage() {
  const [activeTab, setActiveTab] = useState("cipher");
  const [cryptoMode, setCryptoMode] = useState<"encrypt" | "decrypt">("encrypt");
  const [cryptoAlgo, setCryptoAlgo] = useState("Base64");
  const [cryptoInput, setCryptoInput] = useState("");
  const [cryptoKey, setCryptoKey] = useState("");
  const [cryptoOutput, setCryptoOutput] = useState("");
  const [cryptoBusy, setCryptoBusy] = useState(false);

  const [hashAlgo, setHashAlgo] = useState("SHA-256");
  const [hashInput, setHashInput] = useState("");
  const [hashOutput, setHashOutput] = useState("");
  const [hashCompare, setHashCompare] = useState("");
  const [hashBusy, setHashBusy] = useState(false);

  const [pwdLength, setPwdLength] = useState(16);
  const [pwdUppercase, setPwdUppercase] = useState(true);
  const [pwdLowercase, setPwdLowercase] = useState(true);
  const [pwdDigits, setPwdDigits] = useState(true);
  const [pwdSpecial, setPwdSpecial] = useState(true);
  const [generatedPwd, setGeneratedPwd] = useState("");
  const [pwdEntropy, setPwdEntropy] = useState(0);
  const [pwdBusy, setPwdBusy] = useState(false);

  const [hmacAlgo, setHmacAlgo] = useState("SHA-256");
  const [hmacInput, setHmacInput] = useState("");
  const [hmacKey, setHmacKey] = useState("");
  const [hmacOutput, setHmacOutput] = useState("");
  const [hmacBusy, setHmacBusy] = useState(false);

  const [jwtToken, setJwtToken] = useState("");
  const [jwtOutput, setJwtOutput] = useState("");
  const [jwtValid, setJwtValid] = useState<boolean | null>(null);
  const [jwtBusy, setJwtBusy] = useState(false);

  const [rsaKeySize, setRsaKeySize] = useState("2048");
  const [rsaPublicKey, setRsaPublicKey] = useState("");
  const [rsaPrivateKey, setRsaPrivateKey] = useState("");
  const [rsaBusy, setRsaBusy] = useState(false);

  const requiresKey = cryptoAlgo === "AES-256" || cryptoAlgo === "RSA";

  const keyLabel = useMemo(() => {
    if (cryptoAlgo === "AES-256") return "Passphrase";
    if (cryptoAlgo === "RSA") return cryptoMode === "encrypt" ? "RSA Public Key (PEM)" : "RSA Private Key (PEM)";
    return "Key";
  }, [cryptoAlgo, cryptoMode]);

  const runCipher = async () => {
    if (!cryptoInput.trim()) {
      toast.error("Enter input text first.");
      return;
    }
    if (requiresKey && !cryptoKey.trim()) {
      toast.error("A key is required for this algorithm.");
      return;
    }

    try {
      setCryptoBusy(true);
      const payload = {
        operation: cryptoMode,
        algorithm: cryptoAlgo,
        data: cryptoInput,
        key: requiresKey ? cryptoKey : undefined,
      };
      const result = cryptoMode === "encrypt" ? await encryptData(payload) : await decryptData(payload);
      setCryptoOutput(result.result);
      addHistoryEntry({
        moduleType: "crypto",
        inputData: payload,
        outputData: { result: result.result },
      });
      toast.success(`${cryptoMode === "encrypt" ? "Encryption" : "Decryption"} completed.`);
    } catch (error: any) {
      toast.error(error.message || "Cipher operation failed.");
    } finally {
      setCryptoBusy(false);
    }
  };

  const runHash = async () => {
    if (!hashInput.trim()) {
      toast.error("Enter input text first.");
      return;
    }
    try {
      setHashBusy(true);
      const result = await hashData({ operation: "hash", algorithm: hashAlgo, data: hashInput });
      setHashOutput(result.result);
      addHistoryEntry({
        moduleType: "crypto",
        inputData: { operation: "hash", algorithm: hashAlgo, data: hashInput },
        outputData: { result: result.result },
      });
      toast.success("Hash generated.");
    } catch (error: any) {
      toast.error(error.message || "Hashing failed.");
    } finally {
      setHashBusy(false);
    }
  };

  const runPassword = async () => {
    if (!pwdUppercase && !pwdLowercase && !pwdDigits && !pwdSpecial) {
      toast.error("Enable at least one character group.");
      return;
    }
    try {
      setPwdBusy(true);
      const result = await generatePassword({
        length: pwdLength,
        uppercase: pwdUppercase,
        lowercase: pwdLowercase,
        digits: pwdDigits,
        special: pwdSpecial,
      });
      setGeneratedPwd(result.password);
      setPwdEntropy(result.entropy);
      addHistoryEntry({
        moduleType: "crypto",
        inputData: {
          operation: "password_generate",
          length: pwdLength,
          uppercase: pwdUppercase,
          lowercase: pwdLowercase,
          digits: pwdDigits,
          special: pwdSpecial,
        },
        outputData: {
          entropy: result.entropy,
          strength: result.strength,
        },
      });
      toast.success("Password generated.");
    } catch (error: any) {
      toast.error(error.message || "Password generation failed.");
    } finally {
      setPwdBusy(false);
    }
  };

  const runHmac = async () => {
    if (!hmacInput.trim() || !hmacKey.trim()) {
      toast.error("Input text and key are required.");
      return;
    }
    try {
      setHmacBusy(true);
      const result = await generateHmac({ algorithm: hmacAlgo, data: hmacInput, key: hmacKey });
      setHmacOutput(result.result);
      addHistoryEntry({
        moduleType: "crypto",
        inputData: { operation: "hmac", algorithm: hmacAlgo, data: hmacInput },
        outputData: { result: result.result },
      });
      toast.success("HMAC signature created.");
    } catch (error: any) {
      toast.error(error.message || "HMAC generation failed.");
    } finally {
      setHmacBusy(false);
    }
  };

  const runJwtDecode = async () => {
    if (!jwtToken.trim()) {
      toast.error("Paste a JWT token first.");
      return;
    }
    try {
      setJwtBusy(true);
      const result = await decodeJwt(jwtToken.trim());
      setJwtValid(result.valid_format);
      setJwtOutput(JSON.stringify(result, null, 2));
      addHistoryEntry({
        moduleType: "crypto",
        inputData: { operation: "jwt_decode" },
        outputData: { valid_format: result.valid_format, payload_keys: Object.keys(result.payload || {}) },
      });
      toast.success(result.valid_format ? "JWT decoded." : "JWT format is invalid.");
    } catch (error: any) {
      toast.error(error.message || "JWT decode failed.");
    } finally {
      setJwtBusy(false);
    }
  };

  const runRsaGenerate = async () => {
    try {
      setRsaBusy(true);
      const result = await generateRsaKeypair(Number(rsaKeySize));
      setRsaPublicKey(result.public_key_pem);
      setRsaPrivateKey(result.private_key_pem);
      addHistoryEntry({
        moduleType: "crypto",
        inputData: { operation: "rsa_generate_keypair", key_size: Number(rsaKeySize) },
        outputData: { key_size: result.key_size },
      });
      toast.success(`Generated RSA-${result.key_size} keypair.`);
    } catch (error: any) {
      toast.error(error.message || "RSA key generation failed.");
    } finally {
      setRsaBusy(false);
    }
  };

  const entropyLabel = pwdEntropy < 50 ? "Weak" : pwdEntropy < 80 ? "Moderate" : pwdEntropy < 120 ? "Strong" : "Very Strong";
  const entropyVariant = pwdEntropy < 50 ? "destructive" : pwdEntropy < 80 ? "warning" : "success";
  const hashMatches = hashOutput && hashCompare && hashOutput.trim().toLowerCase() === hashCompare.trim().toLowerCase();

  return (
    <MainLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Crypto Helper</h1>
          <p className="text-muted-foreground mt-1">
            Real encryption/decryption, hashing, HMAC signatures, JWT inspection, and secure passwords.
          </p>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList className="grid w-full grid-cols-6 lg:w-[760px]">
            <TabsTrigger value="cipher">Cipher</TabsTrigger>
            <TabsTrigger value="hash">Hash</TabsTrigger>
            <TabsTrigger value="password">Password</TabsTrigger>
            <TabsTrigger value="hmac">HMAC</TabsTrigger>
            <TabsTrigger value="jwt">JWT</TabsTrigger>
            <TabsTrigger value="rsa">RSA Keys</TabsTrigger>
          </TabsList>

          <TabsContent value="cipher">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  {cryptoMode === "encrypt" ? <Lock className="h-5 w-5" /> : <Unlock className="h-5 w-5" />}
                  Cipher Tool
                </CardTitle>
                <CardDescription>
                  Use AES-256-GCM, RSA-OAEP, or encoding transforms for encryption and decoding tasks.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-3">
                  <div className="space-y-2">
                    <Label>Mode</Label>
                    <Select value={cryptoMode} onValueChange={(v) => setCryptoMode(v as "encrypt" | "decrypt")}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="encrypt">Encrypt / Encode</SelectItem>
                        <SelectItem value="decrypt">Decrypt / Decode</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2 md:col-span-2">
                    <Label>Algorithm</Label>
                    <Select value={cryptoAlgo} onValueChange={setCryptoAlgo}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {cipherAlgorithms.map((algo) => <SelectItem key={algo} value={algo}>{algo}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                {requiresKey && (
                  <div className="space-y-2">
                    <Label>{keyLabel}</Label>
                    {cryptoAlgo === "RSA" ? (
                      <Textarea
                        placeholder="Paste PEM key here..."
                        rows={5}
                        value={cryptoKey}
                        onChange={(e) => setCryptoKey(e.target.value)}
                      />
                    ) : (
                      <Input
                        type="password"
                        placeholder="Enter passphrase"
                        value={cryptoKey}
                        onChange={(e) => setCryptoKey(e.target.value)}
                      />
                    )}
                  </div>
                )}

                <div className="space-y-2">
                  <Label>Input</Label>
                  <Textarea
                    rows={5}
                    placeholder={cryptoMode === "encrypt" ? "Enter plaintext..." : "Enter ciphertext..."}
                    value={cryptoInput}
                    onChange={(e) => setCryptoInput(e.target.value)}
                  />
                </div>

                <div className="flex gap-2">
                  <Button onClick={runCipher} disabled={cryptoBusy} className="flex-1">
                    {cryptoBusy ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                    {cryptoMode === "encrypt" ? "Encrypt" : "Decrypt"}
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => {
                      setCryptoInput(cryptoOutput);
                      setCryptoOutput("");
                    }}
                    disabled={!cryptoOutput}
                  >
                    Use Output
                  </Button>
                </div>

                {cryptoOutput && (
                  <div className="space-y-2">
                    <Label>Output</Label>
                    <div className="relative">
                      <Textarea value={cryptoOutput} readOnly rows={5} className="pr-12" />
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute right-2 top-2"
                        onClick={() => copyToClipboard(cryptoOutput).then(() => toast.success("Copied to clipboard."))}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="hash">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Hash className="h-5 w-5" />
                  Hash Generator
                </CardTitle>
                <CardDescription>Generate hashes and verify against an expected hash value.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Algorithm</Label>
                  <Select value={hashAlgo} onValueChange={setHashAlgo}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {hashAlgorithms.map((algo) => <SelectItem key={algo} value={algo}>{algo}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Input</Label>
                  <Textarea rows={5} value={hashInput} onChange={(e) => setHashInput(e.target.value)} placeholder="Enter data..." />
                </div>
                <Button onClick={runHash} disabled={hashBusy} className="w-full">
                  {hashBusy ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                  Generate Hash
                </Button>

                {hashOutput && (
                  <>
                    <div className="space-y-2">
                      <Label>Hash Output</Label>
                      <div className="relative">
                        <Input value={hashOutput} readOnly className="font-mono pr-12" />
                        <Button
                          variant="ghost"
                          size="icon"
                          className="absolute right-2 top-1/2 -translate-y-1/2"
                          onClick={() => copyToClipboard(hashOutput).then(() => toast.success("Copied to clipboard."))}
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>Verify (Optional)</Label>
                      <Input
                        value={hashCompare}
                        onChange={(e) => setHashCompare(e.target.value)}
                        placeholder="Paste expected hash to compare..."
                        className="font-mono"
                      />
                      {hashCompare ? (
                        <Badge variant={hashMatches ? "success" : "destructive"}>
                          {hashMatches ? "Hash Match" : "Hash Mismatch"}
                        </Badge>
                      ) : null}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="password">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <KeyRound className="h-5 w-5" />
                  Password Generator
                </CardTitle>
                <CardDescription>Generate high-entropy passwords with required character diversity.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <Label>Length</Label>
                    <span className="text-sm text-muted-foreground">{pwdLength}</span>
                  </div>
                  <Slider value={[pwdLength]} onValueChange={(v) => setPwdLength(v[0])} min={8} max={128} step={1} />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="flex items-center justify-between"><Label>Uppercase</Label><Switch checked={pwdUppercase} onCheckedChange={setPwdUppercase} /></div>
                  <div className="flex items-center justify-between"><Label>Lowercase</Label><Switch checked={pwdLowercase} onCheckedChange={setPwdLowercase} /></div>
                  <div className="flex items-center justify-between"><Label>Digits</Label><Switch checked={pwdDigits} onCheckedChange={setPwdDigits} /></div>
                  <div className="flex items-center justify-between"><Label>Special</Label><Switch checked={pwdSpecial} onCheckedChange={setPwdSpecial} /></div>
                </div>
                <Button onClick={runPassword} disabled={pwdBusy} className="w-full">
                  {pwdBusy ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                  Generate Password
                </Button>
                {generatedPwd && (
                  <div className="space-y-3">
                    <div className="relative">
                      <Input value={generatedPwd} readOnly className="font-mono pr-12" />
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute right-2 top-1/2 -translate-y-1/2"
                        onClick={() => copyToClipboard(generatedPwd).then(() => toast.success("Copied to clipboard."))}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                    <div className="flex items-center gap-3">
                      <Badge variant={entropyVariant as "destructive" | "warning" | "success"}>{entropyLabel}</Badge>
                      <span className="text-sm text-muted-foreground">{pwdEntropy} bits entropy</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className={cn(
                          "h-full transition-all",
                          pwdEntropy < 50 && "bg-red-500",
                          pwdEntropy >= 50 && pwdEntropy < 80 && "bg-amber-500",
                          pwdEntropy >= 80 && "bg-emerald-500"
                        )}
                        style={{ width: `${Math.min((pwdEntropy / 150) * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="hmac">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5" />
                  HMAC Signature
                </CardTitle>
                <CardDescription>Generate keyed message authentication codes for integrity checks.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Algorithm</Label>
                  <Select value={hmacAlgo} onValueChange={setHmacAlgo}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {hmacAlgorithms.map((algo) => <SelectItem key={algo} value={algo}>{algo}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Key</Label>
                  <Input type="password" value={hmacKey} onChange={(e) => setHmacKey(e.target.value)} placeholder="Shared secret key..." />
                </div>
                <div className="space-y-2">
                  <Label>Message</Label>
                  <Textarea rows={4} value={hmacInput} onChange={(e) => setHmacInput(e.target.value)} placeholder="Message to sign..." />
                </div>
                <Button onClick={runHmac} disabled={hmacBusy} className="w-full">
                  {hmacBusy ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                  Generate HMAC
                </Button>
                {hmacOutput && (
                  <div className="relative">
                    <Input readOnly value={hmacOutput} className="font-mono pr-12" />
                    <Button
                      variant="ghost"
                      size="icon"
                      className="absolute right-2 top-1/2 -translate-y-1/2"
                      onClick={() => copyToClipboard(hmacOutput).then(() => toast.success("Copied to clipboard."))}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="jwt">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5" />
                  JWT Inspector
                </CardTitle>
                <CardDescription>Decode header and payload without signature verification.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>JWT Token</Label>
                  <Textarea rows={5} value={jwtToken} onChange={(e) => setJwtToken(e.target.value)} placeholder="eyJhbGciOi..." />
                </div>
                <Button onClick={runJwtDecode} disabled={jwtBusy} className="w-full">
                  {jwtBusy ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                  Decode JWT
                </Button>
                {jwtValid !== null ? (
                  <Badge variant={jwtValid ? "success" : "destructive"}>{jwtValid ? "Valid JWT format" : "Invalid JWT format"}</Badge>
                ) : null}
                {jwtOutput && (
                  <div className="relative">
                    <Textarea readOnly rows={10} value={jwtOutput} className="font-mono pr-12" />
                    <Button
                      variant="ghost"
                      size="icon"
                      className="absolute right-2 top-2"
                      onClick={() => copyToClipboard(jwtOutput).then(() => toast.success("Copied to clipboard."))}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="rsa">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <KeyRound className="h-5 w-5" />
                  RSA Keypair Generator
                </CardTitle>
                <CardDescription>
                  Generate RSA public/private PEM keys and use them directly in the Cipher tab.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-3">
                  <div className="space-y-2">
                    <Label>Key Size</Label>
                    <Select value={rsaKeySize} onValueChange={setRsaKeySize}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="2048">2048</SelectItem>
                        <SelectItem value="3072">3072</SelectItem>
                        <SelectItem value="4096">4096</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="md:col-span-2 flex items-end">
                    <Button onClick={runRsaGenerate} disabled={rsaBusy} className="w-full">
                      {rsaBusy ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                      Generate RSA Keypair
                    </Button>
                  </div>
                </div>

                {rsaPublicKey ? (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label>Public Key (PEM)</Label>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            setActiveTab("cipher");
                            setCryptoAlgo("RSA");
                            setCryptoMode("encrypt");
                            setCryptoKey(rsaPublicKey);
                          }}
                        >
                          Use for Encrypt
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => copyToClipboard(rsaPublicKey).then(() => toast.success("Public key copied."))}
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                    <Textarea value={rsaPublicKey} readOnly rows={8} className="font-mono text-xs" />
                  </div>
                ) : null}

                {rsaPrivateKey ? (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label>Private Key (PEM)</Label>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            setActiveTab("cipher");
                            setCryptoAlgo("RSA");
                            setCryptoMode("decrypt");
                            setCryptoKey(rsaPrivateKey);
                          }}
                        >
                          Use for Decrypt
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => copyToClipboard(rsaPrivateKey).then(() => toast.success("Private key copied."))}
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                    <Textarea value={rsaPrivateKey} readOnly rows={10} className="font-mono text-xs" />
                  </div>
                ) : null}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  );
}
