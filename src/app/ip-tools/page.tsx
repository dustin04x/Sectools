"use client"

import React, { useState } from 'react';
import { 
  Globe, 
  Search, 
  MapPin, 
  Server, 
  Clock,
  Copy,
  ExternalLink,
  Shield,
  AlertTriangle,
  Network
} from 'lucide-react';
import { MainLayout } from '@/components/layout/main-layout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from 'sonner';
import { dnsLookup, getGeolocation, getReverseDNS, getWHOIS, subnetLookup } from '@/lib/api';
import { copyToClipboard } from '@/lib/utils';
import { addHistoryEntry } from '@/lib/storage';

export default function IPToolsPage() {
  const [activeTab, setActiveTab] = useState('geolocation');
  const [ipInput, setIpInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [dnsRecordType, setDnsRecordType] = useState('A');
  const [subnetInput, setSubnetInput] = useState('');
  
  // Results
  const [geoResult, setGeoResult] = useState<any>(null);
  const [dnsResult, setDnsResult] = useState<any>(null);
  const [whoisResult, setWhoisResult] = useState<any>(null);
  const [dnsLookupResult, setDnsLookupResult] = useState<any>(null);
  const [subnetResult, setSubnetResult] = useState<any>(null);

  const handleGeolocation = async () => {
    if (!ipInput) {
      toast.error('Please enter an IP address or hostname');
      return;
    }
    setLoading(true);
    try {
      const result = await getGeolocation({ ip: ipInput });
      setGeoResult(result);
      addHistoryEntry({
        moduleType: 'ip-tools',
        inputData: { operation: 'geolocation', query: ipInput },
        outputData: {
          ip: result.ip,
          country: result.country || result.country_name,
          city: result.city,
          is_private: result.is_private,
        },
      });
      toast.success('Geolocation lookup complete');
    } catch (error: any) {
      toast.error(error.message || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const handleReverseDNS = async () => {
    if (!ipInput) {
      toast.error('Please enter an IP address');
      return;
    }
    setLoading(true);
    try {
      const result = await getReverseDNS({ ip: ipInput });
      setDnsResult(result);
      addHistoryEntry({
        moduleType: 'ip-tools',
        inputData: { operation: 'reversedns', query: ipInput },
        outputData: { success: result.success, hostname: result.hostname || null },
      });
      toast.success('Reverse DNS lookup complete');
    } catch (error: any) {
      toast.error(error.message || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const handleWHOIS = async () => {
    if (!ipInput) {
      toast.error('Please enter an IP address or domain');
      return;
    }
    setLoading(true);
    try {
      const result = await getWHOIS({ ip: ipInput });
      setWhoisResult(result);
      addHistoryEntry({
        moduleType: 'ip-tools',
        inputData: { operation: 'whois', query: ipInput },
        outputData: {
          registrar: result.registrar,
          creation_date: result.creation_date,
          expiration_date: result.expiration_date,
        },
      });
      toast.success('WHOIS lookup complete');
    } catch (error: any) {
      toast.error(error.message || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDNSLookup = async () => {
    if (!ipInput) {
      toast.error('Please enter a domain name');
      return;
    }
    setLoading(true);
    try {
      const result = await dnsLookup({ domain: ipInput, record_type: dnsRecordType });
      setDnsLookupResult(result);
      addHistoryEntry({
        moduleType: 'ip-tools',
        inputData: { operation: 'dns_lookup', domain: ipInput, record_type: dnsRecordType },
        outputData: {
          records_count: result.records?.length || 0,
          error: result.error,
        },
      });
      toast.success('DNS lookup complete');
    } catch (error: any) {
      toast.error(error.message || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSubnetLookup = async () => {
    if (!subnetInput) {
      toast.error('Please enter CIDR (e.g. 192.168.1.0/24)');
      return;
    }
    setLoading(true);
    try {
      const result = await subnetLookup(subnetInput);
      setSubnetResult(result);
      addHistoryEntry({
        moduleType: 'ip-tools',
        inputData: { operation: 'subnet_lookup', cidr: subnetInput },
        outputData: {
          network: result.network_address,
          total_ips: result.total_ips,
          usable_hosts: result.usable_hosts,
        },
      });
      toast.success('Subnet calculation complete');
    } catch (error: any) {
      toast.error(error.message || 'Calculation failed');
    } finally {
      setLoading(false);
    }
  };

  const handleLookup = () => {
    switch (activeTab) {
      case 'geolocation':
        handleGeolocation();
        break;
      case 'reversedns':
        handleReverseDNS();
        break;
      case 'whois':
        handleWHOIS();
        break;
      case 'dns':
        handleDNSLookup();
        break;
      case 'subnet':
        handleSubnetLookup();
        break;
    }
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">IP Intelligence</h1>
          <p className="text-muted-foreground mt-1">
            Geolocation, reverse DNS, and WHOIS lookups
          </p>
        </div>

        {/* Input Card */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Search className="h-5 w-5" />
              Lookup
            </CardTitle>
            <CardDescription>Enter an IP address or hostname</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              <Input
                placeholder="e.g., 8.8.8.8 or google.com"
                value={ipInput}
                onChange={(e) => setIpInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
                className="flex-1"
              />
              <Button onClick={handleLookup} disabled={loading}>
                <Search className="mr-2 h-4 w-4" />
                {loading ? 'Looking up...' : 'Lookup'}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Results Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList className="grid w-full grid-cols-5 lg:w-[700px]">
            <TabsTrigger value="geolocation">Geolocation</TabsTrigger>
            <TabsTrigger value="reversedns">Reverse DNS</TabsTrigger>
            <TabsTrigger value="whois">WHOIS</TabsTrigger>
            <TabsTrigger value="dns">DNS Lookup</TabsTrigger>
            <TabsTrigger value="subnet">Subnet</TabsTrigger>
          </TabsList>

          {/* Geolocation Results */}
          <TabsContent value="geolocation">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <MapPin className="h-5 w-5" />
                  Geolocation Results
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!geoResult ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <Globe className="h-12 w-12 mx-auto mb-4 opacity-20" />
                    <p>Enter an IP address to see geolocation data</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {geoResult.is_private && (
                      <div className="flex items-center gap-2 p-3 rounded-lg bg-amber-500/10 text-amber-500">
                        <AlertTriangle className="h-5 w-5" />
                        <span>This is a private/RFC1918 address</span>
                      </div>
                    )}
                    
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div className="space-y-1">
                        <Label className="text-muted-foreground">IP Address</Label>
                        <div className="font-mono text-lg">{geoResult.ip}</div>
                      </div>
                      <div className="space-y-1">
                        <Label className="text-muted-foreground">Country</Label>
                        <div className="flex items-center gap-2">
                          <span className="text-lg">{geoResult.country_name || geoResult.country}</span>
                          {geoResult.country && (
                            <Badge variant="outline">{geoResult.country}</Badge>
                          )}
                        </div>
                      </div>
                      <div className="space-y-1">
                        <Label className="text-muted-foreground">City</Label>
                        <div className="text-lg">{geoResult.city || 'N/A'}</div>
                      </div>
                      <div className="space-y-1">
                        <Label className="text-muted-foreground">Region</Label>
                        <div className="text-lg">{geoResult.region || 'N/A'}</div>
                      </div>
                      <div className="space-y-1">
                        <Label className="text-muted-foreground">Timezone</Label>
                        <div className="text-lg">{geoResult.timezone || 'N/A'}</div>
                      </div>
                      <div className="space-y-1">
                        <Label className="text-muted-foreground">ISP</Label>
                        <div className="text-lg">{geoResult.isp || 'N/A'}</div>
                      </div>
                      {geoResult.latitude && geoResult.longitude && (
                        <div className="space-y-1 sm:col-span-2">
                          <Label className="text-muted-foreground">Coordinates</Label>
                          <div className="flex items-center gap-2">
                            <span className="font-mono">{geoResult.latitude}, {geoResult.longitude}</span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                const url = `https://maps.google.com/?q=${geoResult.latitude},${geoResult.longitude}`;
                                window.open(url, '_blank');
                              }}
                            >
                              <ExternalLink className="h-4 w-4 mr-1" />
                              View on Map
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>

                    {geoResult.note && (
                      <>
                        <Separator />
                        <p className="text-sm text-muted-foreground">{geoResult.note}</p>
                      </>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Reverse DNS Results */}
          <TabsContent value="reversedns">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Server className="h-5 w-5" />
                  Reverse DNS Results
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!dnsResult ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <Server className="h-12 w-12 mx-auto mb-4 opacity-20" />
                    <p>Enter an IP address to perform reverse DNS lookup</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="space-y-1">
                      <Label className="text-muted-foreground">IP Address</Label>
                      <div className="font-mono text-lg">{dnsResult.ip}</div>
                    </div>
                    
                    <div className="space-y-1">
                      <Label className="text-muted-foreground">Hostname</Label>
                      <div className="flex items-center gap-2">
                        {dnsResult.success ? (
                          <>
                            <span className="text-lg font-mono">{dnsResult.hostname}</span>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => {
                                copyToClipboard(dnsResult.hostname);
                                toast.success('Copied to clipboard');
                              }}
                            >
                              <Copy className="h-4 w-4" />
                            </Button>
                          </>
                        ) : (
                          <span className="text-lg text-muted-foreground">
                            {dnsResult.error || 'No PTR record found'}
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <div className={dnsResult.success ? 'text-emerald-500' : 'text-amber-500'}>
                        {dnsResult.success ? 'Lookup successful' : 'Lookup failed'}
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* WHOIS Results */}
          <TabsContent value="whois">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  WHOIS Results
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!whoisResult ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <Shield className="h-12 w-12 mx-auto mb-4 opacity-20" />
                    <p>Enter an IP address or domain for WHOIS lookup</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div className="space-y-1">
                        <Label className="text-muted-foreground">Query</Label>
                        <div className="font-mono">{whoisResult.query}</div>
                      </div>
                      <div className="space-y-1">
                        <Label className="text-muted-foreground">Type</Label>
                        <div>{whoisResult.is_ip ? 'IP Address' : 'Domain'}</div>
                      </div>
                      {whoisResult.registrar && (
                        <div className="space-y-1">
                          <Label className="text-muted-foreground">Registrar</Label>
                          <div>{whoisResult.registrar}</div>
                        </div>
                      )}
                      {whoisResult.creation_date && (
                        <div className="space-y-1">
                          <Label className="text-muted-foreground">Creation Date</Label>
                          <div className="flex items-center gap-2">
                            <Clock className="h-4 w-4 text-muted-foreground" />
                            {whoisResult.creation_date}
                          </div>
                        </div>
                      )}
                      {whoisResult.expiration_date && (
                        <div className="space-y-1">
                          <Label className="text-muted-foreground">Expiration Date</Label>
                          <div className="flex items-center gap-2">
                            <Clock className="h-4 w-4 text-muted-foreground" />
                            {whoisResult.expiration_date}
                          </div>
                        </div>
                      )}
                      {whoisResult.name_servers && (
                        <div className="space-y-1 sm:col-span-2">
                          <Label className="text-muted-foreground">Name Servers</Label>
                          <div className="flex flex-wrap gap-2">
                            {whoisResult.name_servers.map((ns: string) => (
                              <Badge key={ns} variant="outline" className="font-mono">
                                {ns}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                      {whoisResult.status && (
                        <div className="space-y-1 sm:col-span-2">
                          <Label className="text-muted-foreground">Status</Label>
                          <div className="flex flex-wrap gap-2">
                            {whoisResult.status.map((s: string) => (
                              <Badge key={s} variant="secondary">
                                {s}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {whoisResult.note && (
                      <>
                        <Separator />
                        <p className="text-sm text-muted-foreground">{whoisResult.note}</p>
                      </>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* DNS Lookup Results */}
          <TabsContent value="dns">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Server className="h-5 w-5" />
                  DNS Lookup
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 sm:grid-cols-3">
                  <div className="sm:col-span-2 space-y-2">
                    <Label>Domain</Label>
                    <Input
                      placeholder="example.com"
                      value={ipInput}
                      onChange={(e) => setIpInput(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Record Type</Label>
                    <Select value={dnsRecordType} onValueChange={setDnsRecordType}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="A">A</SelectItem>
                        <SelectItem value="AAAA">AAAA</SelectItem>
                        <SelectItem value="CNAME">CNAME</SelectItem>
                        <SelectItem value="MX">MX</SelectItem>
                        <SelectItem value="TXT">TXT</SelectItem>
                        <SelectItem value="NS">NS</SelectItem>
                        <SelectItem value="SOA">SOA</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <Button onClick={handleDNSLookup} disabled={loading}>
                  {loading ? 'Looking up...' : 'Lookup DNS'}
                </Button>

                {!dnsLookupResult ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <Server className="h-12 w-12 mx-auto mb-4 opacity-20" />
                    <p>Run a DNS lookup to see records</p>
                  </div>
                ) : dnsLookupResult.error ? (
                  <div className="p-3 rounded border border-amber-500/30 bg-amber-500/10 text-amber-600">
                    {dnsLookupResult.error}
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div className="text-sm text-muted-foreground">
                      TTL: {dnsLookupResult.ttl ?? 'N/A'}
                    </div>
                    <div className="space-y-2">
                      {(dnsLookupResult.records || []).map((record: string) => (
                        <div key={record} className="font-mono text-sm p-2 rounded bg-muted">
                          {record}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Subnet Calculator Results */}
          <TabsContent value="subnet">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Network className="h-5 w-5" />
                  Subnet Calculator
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-2">
                  <Input
                    placeholder="192.168.1.0/24"
                    value={subnetInput}
                    onChange={(e) => setSubnetInput(e.target.value)}
                  />
                  <Button onClick={handleSubnetLookup} disabled={loading}>
                    {loading ? 'Calculating...' : 'Calculate'}
                  </Button>
                </div>

                {!subnetResult ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <Network className="h-12 w-12 mx-auto mb-4 opacity-20" />
                    <p>Enter a CIDR to calculate subnet details</p>
                  </div>
                ) : (
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div><Label className="text-muted-foreground">CIDR</Label><div className="font-mono">{subnetResult.cidr}</div></div>
                    <div><Label className="text-muted-foreground">Network</Label><div className="font-mono">{subnetResult.network_address}</div></div>
                    <div><Label className="text-muted-foreground">Broadcast</Label><div className="font-mono">{subnetResult.broadcast_address || 'N/A'}</div></div>
                    <div><Label className="text-muted-foreground">Netmask</Label><div className="font-mono">{subnetResult.netmask}</div></div>
                    <div><Label className="text-muted-foreground">Hostmask</Label><div className="font-mono">{subnetResult.hostmask}</div></div>
                    <div><Label className="text-muted-foreground">Total IPs</Label><div>{subnetResult.total_ips}</div></div>
                    <div><Label className="text-muted-foreground">Usable Hosts</Label><div>{subnetResult.usable_hosts}</div></div>
                    <div><Label className="text-muted-foreground">Private</Label><div>{subnetResult.is_private ? 'Yes' : 'No'}</div></div>
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
