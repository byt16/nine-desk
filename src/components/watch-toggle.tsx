import { useEffect, useState } from "react";
import { Bookmark } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useWatchlist } from "@/lib/watchlist";
import { cn } from "@/lib/utils";

export function WatchCve({ id }: { id: string }) {
  const [ready, setReady] = useState(false);
  useEffect(() => setReady(true), []);
  const on = useWatchlist((s) => s.cves.includes(id));
  const toggle = useWatchlist((s) => s.toggleCve);
  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      onClick={() => toggle(id)}
      aria-pressed={ready && on}
      className={cn(ready && on && "text-fg")}
    >
      <Bookmark className={cn("size-4", ready && on && "fill-fg")} />
      {ready && on ? "Watching" : "Watch"}
    </Button>
  );
}

export function WatchMisconfig({ slug }: { slug: string }) {
  const [ready, setReady] = useState(false);
  useEffect(() => setReady(true), []);
  const on = useWatchlist((s) => s.misconfigs.includes(slug));
  const toggle = useWatchlist((s) => s.toggleMisconfig);
  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      onClick={() => toggle(slug)}
      aria-pressed={ready && on}
      className={cn(ready && on && "text-fg")}
    >
      <Bookmark className={cn("size-4", ready && on && "fill-fg")} />
      {ready && on ? "Watching" : "Watch"}
    </Button>
  );
}
