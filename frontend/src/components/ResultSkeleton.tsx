import { Card } from "./ui/Card";
import { Skeleton } from "./ui/Skeleton";

export function ResultSkeleton() {
  return (
    <div className="space-y-4">
      <Card className="flex items-center gap-8 p-6">
        <div className="h-40 w-72 animate-pulse rounded-xl bg-[var(--bg-elevated)]" />
        <div className="flex-1 space-y-3">
          <Skeleton lines={3} />
        </div>
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
