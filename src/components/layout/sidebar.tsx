"use client"

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { 
  Shield, 
  ScanLine, 
  Lock, 
  Globe, 
  Terminal, 
  Wrench,
  History, 
  Bookmark,
  Settings,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

interface NavItem {
  id: string;
  label: string;
  icon: React.ElementType;
  href: string;
  description?: string;
}

const mainNavItems: NavItem[] = [
  { 
    id: 'dashboard', 
    label: 'Dashboard', 
    icon: Shield, 
    href: '/',
    description: 'Overview and recent activity'
  },
  { 
    id: 'port-scanner', 
    label: 'Port Scanner', 
    icon: ScanLine, 
    href: '/port-scanner/',
    description: 'TCP port scanning with service detection'
  },
  { 
    id: 'crypto', 
    label: 'Crypto Helper', 
    icon: Lock, 
    href: '/crypto/',
    description: 'Encrypt, decrypt, hash, and encode'
  },
  { 
    id: 'ip-tools', 
    label: 'IP Intelligence', 
    icon: Globe, 
    href: '/ip-tools/',
    description: 'Geolocation, reverse DNS, WHOIS'
  },
  { 
    id: 'rev-shell', 
    label: 'Rev Shell', 
    icon: Terminal, 
    href: '/rev-shell/',
    description: 'Generate reverse shell payloads'
  },
  { 
    id: 'web-tools', 
    label: 'Web Toolkit', 
    icon: Wrench, 
    href: '/web-tools/',
    description: 'HTTP, URL, timestamp, file hash tools'
  },
];

const utilityNavItems: NavItem[] = [
  { 
    id: 'history', 
    label: 'History', 
    icon: History, 
    href: '/history/',
    description: 'View past operations'
  },
  { 
    id: 'bookmarks', 
    label: 'Bookmarks', 
    icon: Bookmark, 
    href: '/bookmarks/',
    description: 'Saved items and payloads'
  },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const pathname = usePathname();

  const NavLink = ({ item }: { item: NavItem }) => {
    const isActive = pathname === item.href;
    const Icon = item.icon;

    const linkContent = (
      <Link
        href={item.href}
        className={cn(
          "flex items-center gap-3 rounded-lg px-3 py-2 transition-all",
          isActive 
            ? "bg-primary text-primary-foreground" 
            : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
          collapsed && "justify-center px-2"
        )}
      >
        <Icon className="h-5 w-5 flex-shrink-0" />
        {!collapsed && <span className="text-sm font-medium">{item.label}</span>}
      </Link>
    );

    if (collapsed) {
      return (
        <Tooltip delayDuration={0}>
          <TooltipTrigger asChild>{linkContent}</TooltipTrigger>
          <TooltipContent side="right" className="flex flex-col gap-1">
            <span className="font-medium">{item.label}</span>
            {item.description && (
              <span className="text-xs text-muted-foreground">{item.description}</span>
            )}
          </TooltipContent>
        </Tooltip>
      );
    }

    return linkContent;
  };

  return (
    <TooltipProvider delayDuration={0}>
      <div
        className={cn(
          "relative flex h-full flex-col border-r bg-card transition-all duration-300",
          collapsed ? "w-16" : "w-64"
        )}
      >
        {/* Header */}
        <div className="flex h-14 items-center border-b px-4">
          {!collapsed && (
            <Link href="/" className="flex items-center gap-2 font-semibold">
              <Shield className="h-6 w-6 text-primary" />
              <span className="text-lg">SecTools</span>
            </Link>
          )}
          {collapsed && (
            <Link href="/" className="mx-auto">
              <Shield className="h-6 w-6 text-primary" />
            </Link>
          )}
        </div>

        {/* Navigation */}
        <ScrollArea className="flex-1 py-4">
          <div className={cn("space-y-1", collapsed ? "px-2" : "px-3")}>
            {!collapsed && (
              <div className="mb-2 px-3 text-xs font-semibold text-muted-foreground">
                Tools
              </div>
            )}
            {mainNavItems.map((item) => (
              <NavLink key={item.id} item={item} />
            ))}
          </div>

          <Separator className="my-4" />

          <div className={cn("space-y-1", collapsed ? "px-2" : "px-3")}>
            {!collapsed && (
              <div className="mb-2 px-3 text-xs font-semibold text-muted-foreground">
                Utilities
              </div>
            )}
            {utilityNavItems.map((item) => (
              <NavLink key={item.id} item={item} />
            ))}
          </div>
        </ScrollArea>

        {/* Footer */}
        <div className="border-t p-3">
          <Tooltip delayDuration={0}>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="w-full"
                onClick={onToggle}
              >
                {collapsed ? (
                  <ChevronRight className="h-4 w-4" />
                ) : (
                  <ChevronLeft className="h-4 w-4" />
                )}
              </Button>
            </TooltipTrigger>
            <TooltipContent side="right">
              {collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            </TooltipContent>
          </Tooltip>
        </div>

        {/* Toggle button (absolute positioned) */}
        <Button
          variant="secondary"
          size="icon"
          className="absolute -right-3 top-20 h-6 w-6 rounded-full border shadow-sm"
          onClick={onToggle}
        >
          {collapsed ? (
            <ChevronRight className="h-3 w-3" />
          ) : (
            <ChevronLeft className="h-3 w-3" />
          )}
        </Button>
      </div>
    </TooltipProvider>
  );
}
