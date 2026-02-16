"use client";

import React, { useEffect, useMemo, useState } from "react";
import { Bookmark, ExternalLink, Tag, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { MainLayout } from "@/components/layout/main-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { Bookmark as BookmarkType } from "@/types";
import { formatDate } from "@/lib/utils";
import { getBookmarks, moduleLabel, modulePath, removeBookmark, updateHistoryBookmark } from "@/lib/storage";

export default function BookmarksPage() {
  const router = useRouter();
  const [bookmarks, setBookmarks] = useState<BookmarkType[]>([]);
  const [query, setQuery] = useState("");
  const [activeTag, setActiveTag] = useState("all");

  useEffect(() => {
    setBookmarks(getBookmarks());
  }, []);

  const tags = useMemo(() => {
    const allTags = new Set<string>();
    bookmarks.forEach((b) => b.tags.forEach((t) => allTags.add(t)));
    return ["all", ...Array.from(allTags)];
  }, [bookmarks]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return bookmarks.filter((item) => {
      const matchesTag = activeTag === "all" || item.tags.includes(activeTag);
      if (!matchesTag) return false;
      if (!q) return true;
      return JSON.stringify(item).toLowerCase().includes(q);
    });
  }, [bookmarks, query, activeTag]);

  const handleDelete = (id: string) => {
    removeBookmark(id);
    updateHistoryBookmark(id, false);
    setBookmarks(getBookmarks());
    toast.success("Bookmark removed.");
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Bookmarks</h1>
            <p className="text-muted-foreground mt-1">Saved operations for quick access.</p>
          </div>
          <Input
            placeholder="Search bookmarks..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-72"
          />
        </div>

        <div className="flex flex-wrap gap-2">
          {tags.map((tag) => (
            <Badge
              key={tag}
              variant={activeTag === tag ? "secondary" : "outline"}
              className="cursor-pointer"
              onClick={() => setActiveTag(tag)}
            >
              {tag}
            </Badge>
          ))}
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {filtered.length === 0 ? (
            <Card className="col-span-full">
              <CardContent className="text-center py-10 text-muted-foreground">
                <Bookmark className="h-12 w-12 mx-auto mb-3 opacity-20" />
                <p>No bookmarks found</p>
                <p className="text-sm mt-1">Save entries from History to manage them here.</p>
              </CardContent>
            </Card>
          ) : (
            filtered.map((item) => (
              <Card key={item.id} className="group">
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between">
                    <Badge variant="outline">{moduleLabel(item.module_type)}</Badge>
                    <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8"
                        onClick={() => router.push(modulePath(item.module_type))}
                      >
                        <ExternalLink className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8"
                        onClick={() => handleDelete(item.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <CardTitle className="text-base">{item.title}</CardTitle>
                  <CardDescription className="truncate">{item.payload}</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap gap-1">
                      {item.tags.map((tag) => (
                        <Badge key={tag} variant="secondary" className="text-xs">
                          <Tag className="h-3 w-3 mr-1" />
                          {tag}
                        </Badge>
                      ))}
                    </div>
                    <span className="text-xs text-muted-foreground">{formatDate(item.created_at)}</span>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      </div>
    </MainLayout>
  );
}
