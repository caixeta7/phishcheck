import { Card } from "./ui/Card";
import { Skeleton } from "./ui/Skeleton";

export function ResultSkeleton() {
  return (
    <div className="space-y-4">
      <Card className="space-y-5 p-6">
        <div className="h-12 w-48 animate-pulse rounded-md bg-[var(--bg-elevated)]" />
        <div className="h-2.5 w-full animate-pulse rounded bg-[var(--bg-elevated)]" />
        <Skeleton lines={2} />
      </Card>
      <Card className="p-5">
        <Skeleton lines={4} />
      </Card>
      <Card className="p-5">
        <Skeleton lines={6} />
      </Card>
    </div>
  );
}
