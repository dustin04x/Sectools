"use client"

import React from 'react';
import Link from 'next/link';
import {
  Shield,
  ScanLine,
  Lock,
  Globe,
  Terminal,
  Wrench,
  ArrowRight,
  Clock,
  Activity,
  Github,
  Linkedin
} from 'lucide-react';
import { MainLayout } from '@/components/layout/main-layout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

const tools = [
  {
    id: 'port-scanner',
    title: 'Port Scanner',
    description: 'Fast multi-threaded TCP port scanning with service detection',
    icon: ScanLine,
    href: '/port-scanner/',
    color: 'text-emerald-500',
    bgColor: 'bg-emerald-500/10',
    status: 'ready',
  },
  {
    id: 'crypto',
    title: 'Crypto Helper',
    description: 'Encrypt, decrypt, hash, and encode data with various algorithms',
    icon: Lock,
    href: '/crypto/',
    color: 'text-blue-500',
    bgColor: 'bg-blue-500/10',
    status: 'ready',
  },
  {
    id: 'ip-tools',
    title: 'IP Intelligence',
    description: 'Geolocation, reverse DNS, and WHOIS lookups',
    icon: Globe,
    href: '/ip-tools/',
    color: 'text-amber-500',
    bgColor: 'bg-amber-500/10',
    status: 'ready',
  },
  {
    id: 'rev-shell',
    title: 'Reverse Shell',
    description: 'Generate reverse shell payloads for various platforms',
    icon: Terminal,
    href: '/rev-shell/',
    color: 'text-purple-500',
    bgColor: 'bg-purple-500/10',
    status: 'ready',
  },
  {
    id: 'web-tools',
    title: 'Web Toolkit',
    description: 'HTTP tester, URL parser, timestamp and file hash utilities',
    icon: Wrench,
    href: '/web-tools/',
    color: 'text-cyan-500',
    bgColor: 'bg-cyan-500/10',
    status: 'ready',
  },
];

const recentActivity = [
  { id: 1, module: 'Port Scanner', action: 'Scanned 192.168.1.1', time: '2 min ago', status: 'success' },
  { id: 2, module: 'Crypto', action: 'Generated SHA-256 hash', time: '15 min ago', status: 'success' },
  { id: 3, module: 'IP Tools', action: 'Lookup 8.8.8.8', time: '1 hour ago', status: 'success' },
];

export default function DashboardPage() {
  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Welcome Section */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
            <p className="text-muted-foreground mt-1">
              Welcome to SecTools - Your unified security toolkit
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="gap-1">
              <Activity className="h-3 w-3" />
              v1.0.0
            </Badge>
          </div>
        </div>

        {/* Tools Grid */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
          {tools.map((tool) => {
            const Icon = tool.icon;
            return (
              <Link key={tool.id} href={tool.href}>
                <Card className="h-full cursor-pointer transition-all hover:shadow-md hover:border-primary/50">
                  <CardHeader className="pb-3">
                    <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center", tool.bgColor)}>
                      <Icon className={cn("h-5 w-5", tool.color)} />
                    </div>
                    <CardTitle className="text-lg mt-3">{tool.title}</CardTitle>
                    <CardDescription className="text-sm line-clamp-2">
                      {tool.description}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center text-sm text-primary">
                      Open tool
                      <ArrowRight className="ml-1 h-4 w-4" />
                    </div>
                  </CardContent>
                </Card>
              </Link>
            );
          })}
        </div>

        {/* Stats & Activity */}
        <div className="grid gap-4 md:grid-cols-2">
          {/* Quick Stats */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Quick Stats</CardTitle>
              <CardDescription>Your activity summary</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-primary">12</div>
                  <div className="text-xs text-muted-foreground">Scans Today</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-primary">48</div>
                  <div className="text-xs text-muted-foreground">Total Operations</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-primary">5</div>
                  <div className="text-xs text-muted-foreground">Bookmarks</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Recent Activity */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Recent Activity</CardTitle>
              <CardDescription>Your latest operations</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {recentActivity.map((activity) => (
                  <div key={activity.id} className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Clock className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <p className="text-sm font-medium">{activity.action}</p>
                        <p className="text-xs text-muted-foreground">{activity.module}</p>
                      </div>
                    </div>
                    <span className="text-xs text-muted-foreground">{activity.time}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Info Banner */}
        <Card className="border-primary/20 bg-primary/5">
          <CardContent className="flex items-center gap-4 py-4">
            <div className="bg-primary/10 p-2 rounded-lg">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            <div className="flex-1">
              <h4 className="font-medium">Privacy-First Design</h4>
              <p className="text-sm text-muted-foreground">
                All processing happens locally on your machine. No data is sent to external servers.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Footer */}
      <footer className="mt-8 border-t pt-6 flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-muted-foreground">
        <p>© 2026 SecTools. Built with ❤️ by Skander.</p>
        <div className="flex items-center gap-6">
          <Link
            href="https://github.com/dustin04x"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 hover:text-primary transition-colors"
          >
            <Github className="h-4 w-4" />
            <span>GitHub</span>
          </Link>
          <Link
            href="https://www.linkedin.com/in/skander-wali-901040391/"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 hover:text-primary transition-colors"
          >
            <Linkedin className="h-4 w-4" />
            <span>LinkedIn</span>
          </Link>
        </div>
      </footer>
    </MainLayout>
  );
}

// Helper function for class names
function cn(...classes: (string | undefined | false)[]) {
  return classes.filter(Boolean).join(' ');
}
