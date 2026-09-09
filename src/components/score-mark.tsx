import { cn } from "@/lib/utils";
import { formatScore } from "@/lib/cvss";

export function ScoreMark({
  score,
  size = "md",
}: {
  score: number;
  size?: "sm" | "md" | "lg";
}) {
  return (
    <span
      className={cn(
        "inline-flex font-mono font-medium tabular-nums text-critical",
        size === "sm" && "text-sm",
        size === "md" && "text-lg",
        size === "lg" && "text-4xl tracking-tight sm:text-5xl",
      )}
    >
      {formatScore(score)}
    </span>
  );
}
