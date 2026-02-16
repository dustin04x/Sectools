"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Command, Moon, RefreshCw, Search, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import { Button } from "@/components/ui/button";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import { cn } from "@/lib/utils";
import { checkBackendStatus, getBackendPort, restartBackend } from "@/lib/api";
import { toast } from "sonner";

interface HeaderProps {
  onMenuClick?: () => void;
}

const commandItems = [
  {
    group: "Tools",
    items: [
      { label: "Port Scanner", href: "/port-scanner/", shortcut: "Ctrl+1" },
      { label: "Crypto Helper", href: "/crypto/", shortcut: "Ctrl+2" },
      { label: "IP Intelligence", href: "/ip-tools/", shortcut: "Ctrl+3" },
      { label: "Reverse Shell", href: "/rev-shell/", shortcut: "Ctrl+4" },
      { label: "Web Toolkit", href: "/web-tools/", shortcut: "Ctrl+5" },
    ],
  },
  {
    group: "Utilities",
    items: [
      { label: "History", href: "/history/", shortcut: "Ctrl+H" },
      { label: "Bookmarks", href: "/bookmarks/", shortcut: "Ctrl+B" },
      { label: "Dashboard", href: "/", shortcut: "Ctrl+D" },
    ],
  },
];

export function Header({ onMenuClick }: HeaderProps) {
  const router = useRouter();
  const { theme, setTheme } = useTheme();
  const [open, setOpen] = useState(false);
  const [backendStatus, setBackendStatus] = useState<"online" | "offline" | "checking">("checking");
  const [pythonPort, setPythonPort] = useState<number | null>(null);

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };

    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  useEffect(() => {
    checkBackendHealth();
    const interval = setInterval(checkBackendHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const checkBackendHealth = async () => {
    try {
      const currentPort = pythonPort ?? (await getBackendPort());
      if (!pythonPort) setPythonPort(currentPort);
      const isHealthy = await checkBackendStatus(currentPort);
      setBackendStatus(isHealthy ? "online" : "offline");
    } catch {
      setBackendStatus("offline");
    }
  };

  const handleRestartBackend = async () => {
    try {
      toast.info("Restarting backend...");
      const newPort = await restartBackend();
      setPythonPort(newPort);
      setBackendStatus("online");
      toast.success("Backend restarted successfully");
    } catch {
      toast.error("Failed to restart backend");
    }
  };

  const handleSelect = (href: string) => {
    setOpen(false);
    router.push(href);
  };

  return (
    <header className="flex h-14 items-center gap-4 border-b bg-card px-6">
      <Button
        variant="outline"
        className="relative h-9 w-full justify-start rounded-md bg-muted/50 text-sm font-normal text-muted-foreground shadow-none hover:bg-muted sm:pr-12 md:w-40 lg:w-64"
        onClick={() => setOpen(true)}
      >
        <Search className="mr-2 h-4 w-4" />
        Search...
        <kbd className="pointer-events-none absolute right-1.5 top-1.5 hidden h-6 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-xs font-medium opacity-100 sm:flex">
          <span className="text-xs">Ctrl</span>K
        </kbd>
      </Button>

      <CommandDialog open={open} onOpenChange={setOpen}>
        <CommandInput placeholder="Type a command or search..." />
        <CommandList>
          <CommandEmpty>No results found.</CommandEmpty>
          {commandItems.map((group) => (
            <React.Fragment key={group.group}>
              <CommandGroup heading={group.group}>
                {group.items.map((item) => (
                  <CommandItem key={item.label} onSelect={() => handleSelect(item.href)}>
                    <Command className="mr-2 h-4 w-4" />
                    <span>{item.label}</span>
                    <CommandShortcut>{item.shortcut}</CommandShortcut>
                  </CommandItem>
                ))}
              </CommandGroup>
              <CommandSeparator />
            </React.Fragment>
          ))}
        </CommandList>
      </CommandDialog>

      <div className="ml-auto flex items-center gap-2">
        <div className="mr-4 flex items-center gap-2">
          <div
            className={cn(
              "h-2 w-2 rounded-full",
              backendStatus === "online" && "bg-emerald-500",
              backendStatus === "offline" && "bg-red-500",
              backendStatus === "checking" && "bg-amber-500 animate-pulse"
            )}
          />
          <span
            className={cn(
              "hidden text-xs font-medium sm:inline",
              backendStatus === "online" && "text-emerald-500",
              backendStatus === "offline" && "text-red-500",
              backendStatus === "checking" && "text-muted-foreground"
            )}
          >
            Backend {backendStatus}
          </span>
          {backendStatus === "offline" && (
            <Button variant="ghost" size="icon" className="h-6 w-6" onClick={handleRestartBackend}>
              <RefreshCw className="h-3 w-3" />
            </Button>
          )}
        </div>

        <Button variant="ghost" size="icon" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
          <Sun className="h-4 w-4 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
          <Moon className="absolute h-4 w-4 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
          <span className="sr-only">Toggle theme</span>
        </Button>
      </div>
    </header>
  );
}
