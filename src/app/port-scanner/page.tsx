"use client"

import React, { useState, useCallback } from 'react';
import { 
  ScanLine, 
  Play, 
  Download, 
  Copy, 
  Save,
  Globe,
  Clock,
  Activity,
  CheckCircle2,
  XCircle,
  Filter,
  Search
} from 'lucide-react';
import { MainLayout } from '@/components/layout/main-layout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Slider } from '@/components/ui/slider';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { toast } from 'sonner';
import { scanPorts, PortScanResponse, PortScanResult } from '@/lib/api';
import { cn, formatDuration, downloadAsFile, copyToClipboard } from '@/lib/utils';
import { addHistoryEntry } from '@/lib/storage';

interface ScanState {
  isScanning: boolean;
  progress: number;
  currentPort: number;
}

export default function PortScannerPage() {
  // Form state
  const [target, setTarget] = useState('');
  const [startPort, setStartPort] = useState(1);
  const [endPort, setEndPort] = useState(1000);
  const [threads, setThreads] = useState(100);
  const [timeout, setTimeout] = useState(1.0);
  
  // Scan state
  const [scanState, setScanState] = useState<ScanState>({
    isScanning: false,
    progress: 0,
    currentPort: 0,
  });
  
  // Results
  const [result, setResult] = useState<PortScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Filter
  const [filter, setFilter] = useState('');

  const handleScan = async () => {
    if (!target) {
      toast.error('Please enter a target IP or hostname');
      return;
    }

    setError(null);
    setResult(null);
    setScanState({ isScanning: true, progress: 0, currentPort: startPort });

    try {
      // Simulate progress updates
      const progressInterval = setInterval(() => {
        setScanState(prev => ({
          ...prev,
          progress: Math.min(prev.progress + Math.random() * 5, 90),
        }));
      }, 500);

      const response = await scanPorts({
        target,
        start_port: startPort,
        end_port: endPort,
        threads,
        timeout,
      });

      clearInterval(progressInterval);
      setScanState({ isScanning: false, progress: 100, currentPort: endPort });
      setResult(response);
      addHistoryEntry({
        moduleType: 'port-scanner',
        inputData: { target, start_port: startPort, end_port: endPort, threads, timeout },
        outputData: {
          open_ports_count: response.open_ports.length,
          elapsed_time: response.elapsed_time,
          resolved_ip: response.resolved_ip,
        },
      });
      
      toast.success(`Scan complete! Found ${response.open_ports.length} open ports`);
    } catch (err: any) {
      setScanState({ isScanning: false, progress: 0, currentPort: 0 });
      setError(err.message || 'Scan failed');
      toast.error(err.message || 'Scan failed');
    }
  };

  const handleExport = (format: 'json' | 'csv') => {
    if (!result) return;

    if (format === 'json') {
      const content = JSON.stringify(result, null, 2);
      downloadAsFile(content, `scan-${result.target}-${Date.now()}.json`, 'application/json');
    } else {
      // CSV format
      const headers = 'Port,Status,Service,Banner\n';
      const rows = result.open_ports.map(p => 
        `${p.port},${p.status},"${p.service || 'Unknown'}","${p.banner || ''}"`
      ).join('\n');
      const content = headers + rows;
      downloadAsFile(content, `scan-${result.target}-${Date.now()}.csv`, 'text/csv');
    }
    
    toast.success(`Exported as ${format.toUpperCase()}`);
  };

  const handleCopyResults = () => {
    if (!result) return;
    const text = result.open_ports.map(p => 
      `${p.port}/tcp ${p.status} ${p.service || ''}`
    ).join('\n');
    copyToClipboard(text);
    toast.success('Results copied to clipboard');
  };

  const filteredPorts = result?.open_ports.filter(port => 
    filter === '' || 
    port.port.toString().includes(filter) ||
    (port.service && port.service.toLowerCase().includes(filter.toLowerCase()))
  ) || [];

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Port Scanner</h1>
            <p className="text-muted-foreground mt-1">
              Fast multi-threaded TCP port scanning with service detection
            </p>
          </div>
          {result && (
            <div className="flex gap-2">
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" onClick={handleCopyResults}>
                      <Copy className="h-4 w-4" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Copy results</TooltipContent>
                </Tooltip>
              </TooltipProvider>
              <Button variant="outline" onClick={() => handleExport('json')}>
                <Download className="mr-2 h-4 w-4" />
                JSON
              </Button>
              <Button variant="outline" onClick={() => handleExport('csv')}>
                <Download className="mr-2 h-4 w-4" />
                CSV
              </Button>
            </div>
          )}
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          {/* Configuration Panel */}
          <Card className="lg:col-span-1">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <ScanLine className="h-5 w-5" />
                Configuration
              </CardTitle>
              <CardDescription>Configure scan parameters</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Target */}
              <div className="space-y-2">
                <Label htmlFor="target">Target</Label>
                <Input
                  id="target"
                  placeholder="IP or hostname (e.g., 192.168.1.1)"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={scanState.isScanning}
                />
              </div>

              {/* Port Range */}
              <div className="space-y-2">
                <Label>Port Range</Label>
                <div className="flex gap-2">
                  <Input
                    type="number"
                    min={1}
                    max={65535}
                    value={startPort}
                    onChange={(e) => setStartPort(parseInt(e.target.value) || 1)}
                    disabled={scanState.isScanning}
                    className="flex-1"
                  />
                  <span className="flex items-center text-muted-foreground">to</span>
                  <Input
                    type="number"
                    min={1}
                    max={65535}
                    value={endPort}
                    onChange={(e) => setEndPort(parseInt(e.target.value) || 1000)}
                    disabled={scanState.isScanning}
                    className="flex-1"
                  />
                </div>
              </div>

              {/* Threads */}
              <div className="space-y-2">
                <div className="flex justify-between">
                  <Label>Threads</Label>
                  <span className="text-sm text-muted-foreground">{threads}</span>
                </div>
                <Slider
                  value={[threads]}
                  onValueChange={(v) => setThreads(v[0])}
                  min={10}
                  max={500}
                  step={10}
                  disabled={scanState.isScanning}
                />
              </div>

              {/* Timeout */}
              <div className="space-y-2">
                <div className="flex justify-between">
                  <Label>Timeout (seconds)</Label>
                  <span className="text-sm text-muted-foreground">{timeout}s</span>
                </div>
                <Slider
                  value={[timeout]}
                  onValueChange={(v) => setTimeout(v[0])}
                  min={0.5}
                  max={10}
                  step={0.5}
                  disabled={scanState.isScanning}
                />
              </div>

              {/* Quick Presets */}
              <div className="space-y-2">
                <Label>Quick Presets</Label>
                <div className="flex flex-wrap gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => { setStartPort(1); setEndPort(1000); }}
                    disabled={scanState.isScanning}
                  >
                    Common (1-1000)
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => { setStartPort(1); setEndPort(100); }}
                    disabled={scanState.isScanning}
                  >
                    Top 100
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => { setStartPort(1); setEndPort(65535); }}
                    disabled={scanState.isScanning}
                  >
                    Full Range
                  </Button>
                </div>
              </div>
            </CardContent>
            <CardFooter>
              <Button 
                className="w-full" 
                onClick={handleScan}
                disabled={scanState.isScanning || !target}
              >
                {scanState.isScanning ? (
                  <>
                    <Activity className="mr-2 h-4 w-4 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Play className="mr-2 h-4 w-4" />
                    Start Scan
                  </>
                )}
              </Button>
            </CardFooter>
          </Card>

          {/* Results Panel */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="text-lg">Scan Results</CardTitle>
              <CardDescription>
                {result ? `Found ${result.open_ports.length} open ports on ${result.target}` : 'No scan results yet'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {/* Progress */}
              {scanState.isScanning && (
                <div className="mb-4 space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Scanning port {scanState.currentPort}...</span>
                    <span>{Math.round(scanState.progress)}%</span>
                  </div>
                  <Progress value={scanState.progress} />
                </div>
              )}

              {/* Error */}
              {error && (
                <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 text-destructive">
                  <div className="flex items-center gap-2">
                    <XCircle className="h-5 w-5" />
                    <span className="font-medium">Error: {error}</span>
                  </div>
                </div>
              )}

              {/* Results */}
              {result && (
                <Tabs defaultValue="table" className="space-y-4">
                  <TabsList>
                    <TabsTrigger value="table">Table View</TabsTrigger>
                    <TabsTrigger value="nmap">Nmap Style</TabsTrigger>
                    <TabsTrigger value="summary">Summary</TabsTrigger>
                  </TabsList>

                  <TabsContent value="table" className="space-y-4">
                    {/* Filter */}
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                      <Input
                        placeholder="Filter by port or service..."
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        className="pl-9"
                      />
                    </div>

                    {/* Results Table */}
                    <ScrollArea className="h-[400px] rounded-md border">
                      <table className="w-full">
                        <thead className="bg-muted">
                          <tr>
                            <th className="px-4 py-2 text-left text-sm font-medium">Port</th>
                            <th className="px-4 py-2 text-left text-sm font-medium">Status</th>
                            <th className="px-4 py-2 text-left text-sm font-medium">Service</th>
                            <th className="px-4 py-2 text-left text-sm font-medium">Banner</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredPorts.length === 0 ? (
                            <tr>
                              <td colSpan={4} className="px-4 py-8 text-center text-muted-foreground">
                                No open ports found
                              </td>
                            </tr>
                          ) : (
                            filteredPorts.map((port) => (
                              <tr key={port.port} className="border-t">
                                <td className="px-4 py-2 font-mono text-sm">{port.port}</td>
                                <td className="px-4 py-2">
                                  <Badge variant="success" className="gap-1">
                                    <CheckCircle2 className="h-3 w-3" />
                                    {port.status}
                                  </Badge>
                                </td>
                                <td className="px-4 py-2 text-sm">{port.service || 'Unknown'}</td>
                                <td className="px-4 py-2 text-sm text-muted-foreground truncate max-w-[200px]">
                                  {port.banner || '-'}
                                </td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </ScrollArea>
                  </TabsContent>

                  <TabsContent value="nmap">
                    <ScrollArea className="h-[400px] rounded-md border bg-black/50 p-4">
                      <pre className="font-mono text-sm text-green-400">
                        {`Starting Nmap-style scan at ${new Date(result.scan_time).toLocaleString()}
Nmap scan report for ${result.target} (${result.resolved_ip})
Host is up (${result.elapsed_time}s latency).
Not shown: ${result.total_scanned - result.open_ports.length} closed ports

PORT     STATE SERVICE
${result.open_ports.map(p => 
  `${p.port.toString().padEnd(8)} ${p.status.padEnd(6)} ${p.service || 'unknown'}`
).join('\n')}

Scan completed in ${result.elapsed_time} seconds`}
                      </pre>
                    </ScrollArea>
                  </TabsContent>

                  <TabsContent value="summary">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm font-medium">Target</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex items-center gap-2">
                            <Globe className="h-4 w-4 text-muted-foreground" />
                            <span className="font-mono">{result.target}</span>
                          </div>
                          <div className="text-sm text-muted-foreground mt-1">
                            Resolved: {result.resolved_ip}
                          </div>
                        </CardContent>
                      </Card>
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm font-medium">Scan Time</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex items-center gap-2">
                            <Clock className="h-4 w-4 text-muted-foreground" />
                            <span>{formatDuration(result.elapsed_time)}</span>
                          </div>
                          <div className="text-sm text-muted-foreground mt-1">
                            {new Date(result.scan_time).toLocaleString()}
                          </div>
                        </CardContent>
                      </Card>
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm font-medium">Ports Scanned</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-2xl font-bold">{result.total_scanned.toLocaleString()}</div>
                        </CardContent>
                      </Card>
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm font-medium">Open Ports</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-2xl font-bold text-emerald-500">
                            {result.open_ports.length}
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>
                </Tabs>
              )}

              {/* Empty State */}
              {!result && !scanState.isScanning && !error && (
                <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                  <ScanLine className="h-16 w-16 mb-4 opacity-20" />
                  <p>Enter a target and click Start Scan</p>
                  <p className="text-sm mt-1">Results will appear here</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </MainLayout>
  );
}
