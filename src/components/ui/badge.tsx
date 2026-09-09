import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-sm px-1.5 py-0.5 font-mono text-xs font-medium tabular-nums tracking-wide",
  {
    variants: {
      tone: {
        default: "bg-surface-2 text-muted",
        fg: "bg-fg text-bg",
        critical: "bg-critical/15 text-critical",
        ok: "bg-ok/15 text-ok",
        outline: "shadow-[var(--shadow-border)] text-muted",
      },
    },
    defaultVariants: { tone: "default" },
  },
);

export function Badge({
  className,
  tone,
  ...props
}: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
