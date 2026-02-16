"use client";

import React, { useEffect, useMemo, useState } from "react";
import { Bookmark, Clock, ExternalLink, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { MainLayout } from "@/components/layout/main-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { formatDate } from "@/lib/utils";
import {
  addBookmarkFromHistory,
  clearHistory,
  deleteHistoryEntry,
  getHistory,
  moduleLabel,
  modulePath,
  removeBookmark,
  updateHistoryBookmark,
} from "@/lib/storage";
import { HistoryEntry } from "@/types";

export default function HistoryPage() {
  const router = useRouter();
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [query, setQuery] = useState("");

  useEffect(() => {
    setHistory(getHistory());
  }, []);

  const filteredHistory = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return history;
    return history.filter((item) => {
      const haystack = JSON.stringify(item).toLowerCase();
      return haystack.includes(q);
    });
  }, [history, query]);

  const handleClearHistory = () => {
    clearHistory();
    setHistory([]);
    toast.success("History cleared.");
  };

  const handleToggleBookmark = (item: HistoryEntry) => {
    const next = !item.bookmarked;
    const updated = updateHistoryBookmark(item.id, next);
    if (!updated) return;

    if (next) {
      addBookmarkFromHistory(updated);
      toast.success("Saved to bookmarks.");
    } else {
      removeBookmark(item.id);
      toast.info("Removed from bookmarks.");
    }
    setHistory(getHistory());
  };

  const handleDelete = (id: string) => {
    deleteHistoryEntry(id);
    setHistory(getHistory());
    removeBookmark(id);
    toast.success("Entry deleted.");
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">History</h1>
            <p className="text-muted-foreground mt-1">
              Recent operations from all modules, stored locally in your browser.
            </p>
          </div>
          <Button variant="outline" onClick={handleClearHistory}>
            <Trash2 className="mr-2 h-4 w-4" />
            Clear History
          </Button>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Clock className="h-5 w-5" />
              Recent Operations
            </CardTitle>
            <CardDescription>Filter by module, input, output, or timestamp</CardDescription>
          </CardHeader>
          <CardContent>
            <Input
              placeholder="Search history..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="mb-4"
            />

            <div className="space-y-3">
              {filteredHistory.length === 0 ? (
                <div className="text-center py-10 text-muted-foreground">
                  <Clock className="h-12 w-12 mx-auto mb-3 opacity-20" />
                  <p>No history yet</p>
                  <p className="text-sm mt-1">Run a tool and entries will appear here.</p>
                </div>
              ) : (
                filteredHistory.map((item) => (
                  <div
                    key={item.id}
                    className="flex items-center justify-between rounded-lg border p-4 hover:bg-accent/40 transition-colors"
                  >
                    <div className="space-y-1 min-w-0">
                      <Badge variant="outline">{moduleLabel(item.module_type)}</Badge>
                      <p className="text-sm text-muted-foreground truncate">
                        Input: {JSON.stringify(item.input_data)}
                      </p>
                      <p className="text-sm text-muted-foreground truncate">
                        Output: {JSON.stringify(item.output_data)}
                      </p>
                      <p className="text-xs text-muted-foreground">{formatDate(item.timestamp)}</p>
                    </div>

                    <div className="flex items-center gap-1">
                      <Button variant="ghost" size="icon" onClick={() => handleToggleBookmark(item)}>
                        <Bookmark className={item.bookmarked ? "h-4 w-4 fill-current" : "h-4 w-4"} />
                      </Button>
                      <Button variant="ghost" size="icon" onClick={() => router.push(modulePath(item.module_type))}>
                        <ExternalLink className="h-4 w-4" />
                      </Button>
                      <Button variant="ghost" size="icon" onClick={() => handleDelete(item.id)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
