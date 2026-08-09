import clsx from "clsx";

interface Props {
  className?: string;
  lines?: number;
}

export function Skeleton({ className, lines = 1 }: Props) {
  return (
    <div className={clsx("space-y-2", className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className="animate-pulse rounded-md bg-[var(--bg-elevated)]"
          style={{ height: `${12 + Math.random() * 8}px`, width: `${60 + Math.random() * 35}%` }}
        />
      ))}
    </div>
  );
}
