import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useApi } from "../api";
import type { Telemetry } from "../types";
import { Empty, ErrorState, Skeleton } from "./ui";
export default function ActivityChart() {
  const query = useApi<Telemetry>("/telemetry", 5000);
  if (query.error)
    return (
      <ErrorState error={query.error} retry={() => void query.refetch()} />
    );
  if (!query.data) return <Skeleton rows={4} />;
  const data = query.data.queries.map((queries, i) => ({
    second: i - 59,
    Queries: queries,
    Blocked: query.data.blocked[i] ?? 0,
    Cached: query.data.cache[i] ?? 0,
  }));
  if (!data.some((d) => d.Queries > 0))
    return (
      <Empty title="No queries in the last minute">
        Traffic will appear here as devices use AegisDNS.
      </Empty>
    );
  return (
    <div
      className="activity-chart"
      role="img"
      aria-label={`Queries per second over the last 60 seconds: ${data.reduce((a, d) => a + d.Queries, 0)} queries, ${data.reduce((a, d) => a + d.Blocked, 0)} blocked.`}
    >
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={data}
          margin={{ top: 15, right: 10, left: -25, bottom: 0 }}
        >
          <defs>
            <linearGradient id="traffic-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--info)" stopOpacity={0.25} />
              <stop offset="100%" stopColor="var(--info)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid
            vertical={false}
            stroke="var(--border)"
            strokeDasharray="3 5"
          />
          <XAxis
            dataKey="second"
            ticks={[-59, -45, -30, -15, 0]}
            tickFormatter={(n) => (n === 0 ? "Now" : `${Math.abs(n)}s ago`)}
            axisLine={false}
            tickLine={false}
            tick={{ fill: "var(--text-muted)", fontSize: 12 }}
            dy={10}
          />
          <YAxis
            allowDecimals={false}
            axisLine={false}
            tickLine={false}
            tick={{ fill: "var(--text-muted)", fontSize: 12 }}
          />
          <Tooltip
            contentStyle={{
              background: "var(--surface-elevated)",
              border: "1px solid var(--border)",
              borderRadius: 8,
              color: "var(--text-primary)",
            }}
            labelFormatter={(n) => `${Math.abs(Number(n))} seconds ago`}
          />
          <Area
            type="monotone"
            dataKey="Queries"
            stroke="var(--info)"
            strokeWidth={2}
            fill="url(#traffic-fill)"
            isAnimationActive={false}
          />
          <Area
            type="monotone"
            dataKey="Blocked"
            stroke="var(--danger)"
            strokeWidth={1.5}
            fill="transparent"
            isAnimationActive={false}
          />
          <Area
            type="monotone"
            dataKey="Cached"
            stroke="var(--cached)"
            fill="transparent"
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
