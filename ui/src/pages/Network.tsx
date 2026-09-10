import { useMemo, useState } from "react";
import {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  type NodeProps,
  type Node as FlowNode,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Globe2, Monitor, Network as NetworkIcon, Shield } from "lucide-react";
import { number, useApi } from "../api";
import type { Graph, GraphNode } from "../types";
import {
  Button,
  Empty,
  ErrorState,
  Field,
  PageHeader,
  Panel,
  Skeleton,
  Badge,
} from "../components/ui";

type RelationshipNode = FlowNode<{
  label: string;
  kind: string;
  count: number;
}>;
function NodeView({ data }: NodeProps<RelationshipNode>) {
  const Icon =
    data.kind === "device"
      ? Monitor
      : data.kind === "blocklist" || data.kind === "company"
        ? Shield
        : Globe2;
  return (
    <div className={`relationship-node kind-${data.kind}`}>
      <Handle type="target" position={Position.Left} />
      <Icon size={17} />
      <div>
        <small>{data.kind}</small>
        <strong title={data.label}>{data.label}</strong>
      </div>
      <span>{number(data.count)}</span>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
const nodeTypes = { relationship: NodeView };
export default function Network() {
  const initial =
    new URLSearchParams(location.hash.split("?")[1]).get("domain") || "";
  const [input, setInput] = useState(initial),
    [domain, setDomain] = useState(initial),
    [hours, setHours] = useState("24"),
    [limit, setLimit] = useState("60"),
    [minCount, setMinCount] = useState("1"),
    [selected, setSelected] = useState<GraphNode | null>(null),
    [device, setDevice] = useState("");
  const query = useApi<Graph>(
    `/graph?hours=${hours}&limit=${limit}&min_count=${minCount}&domain=${encodeURIComponent(domain)}`,
    15000,
  );
  const layout = useMemo(() => {
    if (!query.data) return { nodes: [], edges: [] };
    let raw = query.data.nodes,
      edges = [...query.data.edges].sort(
        (a, b) => b.count - a.count || b.last_seen.localeCompare(a.last_seen),
      );
    if (device) {
      const reached = new Set([device]);
      for (let pass = 0; pass < 3; pass++) {
        const next = new Set(reached);
        for (const e of edges) {
          if (reached.has(e.source)) next.add(e.target);
          if (reached.has(e.target)) next.add(e.source);
        }
        for (const n of next) reached.add(n);
      }
      raw = raw.filter(
        (n) => reached.has(n.id) && (n.kind !== "device" || n.id === device),
      );
      const visible = new Set(raw.map((n) => n.id));
      edges = edges.filter(
        (e) => visible.has(e.source) && visible.has(e.target),
      );
    }
    const connected = new Set(edges.flatMap((e) => [e.source, e.target]));
    raw = raw
      .filter((n) => connected.has(n.id))
      .sort((a, b) => {
        const score = (id: string) =>
          edges
            .filter((e) => e.source === id || e.target === id)
            .reduce((sum, e) => sum + e.count, 0);
        return score(b.id) - score(a.id);
      });
    const columns = new Map<number, number>();
    const nodes = raw.map((n) => {
      const column =
        n.kind === "device"
          ? 0
          : n.kind === "domain"
            ? edges.some(
                (e) => e.target === n.id && e.relation === "canonical_name",
              )
              ? 2
              : 1
            : [
                  "ip",
                  "company",
                  "application",
                  "nameserver",
                  "blocklist",
                ].includes(n.kind)
              ? 3
              : 4;
      const row = columns.get(column) || 0;
      columns.set(column, row + 1);
      const lane = Math.floor(row / 12);
      return {
        id: n.id,
        type: "relationship",
        position: { x: column * 680 + lane * 270, y: (row % 12) * 95 },
        data: {
          label: n.label,
          kind: n.kind,
          count: edges
            .filter((e) => e.source === n.id || e.target === n.id)
            .reduce((a, e) => a + e.count, 0),
        },
        selected: selected?.id === n.id,
      };
    });
    return {
      nodes,
      edges: edges.map((e, i) => ({
        id: `${e.source}-${e.target}-${i}`,
        source: e.source,
        target: e.target,
        label:
          selected && (e.source === selected.id || e.target === selected.id)
            ? e.relation.replaceAll("_", " ")
            : undefined,
        style: {
          stroke:
            selected && (e.source === selected.id || e.target === selected.id)
              ? "var(--accent)"
              : "var(--border)",
          strokeWidth: 1.5,
        },
        labelStyle: { fill: "var(--text-secondary)", fontSize: 11 },
        labelBgStyle: { fill: "var(--surface)" },
      })),
    };
  }, [query.data, selected, device]);
  const connections =
    query.data?.edges.filter(
      (e) => e.source === selected?.id || e.target === selected?.id,
    ) || [];
  return (
    <>
      <PageHeader
        eyebrow="OBSERVE / RELATIONSHIPS"
        title="Follow the connections."
        description="Trace observed links between devices, domains, addresses, and infrastructure."
        action={
          <Badge tone="info">
            {number(query.data?.nodes.length)} observed entities
          </Badge>
        }
      />
      <div className="filter-bar standalone">
        <form
          className="graph-search"
          onSubmit={(e) => {
            e.preventDefault();
            setDomain(input.trim());
            setSelected(null);
          }}
        >
          <input
            aria-label="Domain to investigate"
            placeholder="Investigate a domain…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
          <Button type="submit" variant="primary">
            Investigate
          </Button>
        </form>
        <select
          aria-label="Relationship history"
          value={hours}
          onChange={(e) => setHours(e.target.value)}
        >
          <option value="1">Last hour</option>
          <option value="6">Last 6 hours</option>
          <option value="24">Last 24 hours</option>
          <option value="168">Last 7 days</option>
          <option value="720">Last 30 days</option>
        </select>
        <select
          aria-label="Focus device"
          value={device}
          onChange={(e) => setDevice(e.target.value)}
        >
          <option value="">All devices</option>
          {query.data?.nodes
            .filter((n) => n.kind === "device")
            .map((n) => (
              <option value={n.id} key={n.id}>
                {n.label}
              </option>
            ))}
        </select>
        <select
          aria-label="Minimum observations"
          value={minCount}
          onChange={(e) => {
            setMinCount(e.target.value);
            setSelected(null);
          }}
        >
          <option value="1">All activity</option>
          <option value="5">5+ observations</option>
          <option value="20">20+ observations</option>
          <option value="100">100+ observations</option>
        </select>
        <select
          aria-label="Graph size"
          value={limit}
          onChange={(e) => {
            setLimit(e.target.value);
            setSelected(null);
          }}
        >
          <option value="30">30 connections</option>
          <option value="60">60 connections</option>
          <option value="120">120 connections</option>
          <option value="200">200 connections</option>
        </select>
        {(domain || device) && (
          <Button
            onClick={() => {
              setDomain("");
              setInput("");
              setDevice("");
              setSelected(null);
            }}
          >
            Clear
          </Button>
        )}
      </div>
      {query.error ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : !query.data ? (
        <Skeleton rows={9} />
      ) : (
        <div className="graph-layout">
          <Panel className="graph-canvas">
            {layout.nodes.length ? (
              <ReactFlow
                key={`${domain}-${hours}-${device}`}
                nodes={layout.nodes}
                edges={layout.edges}
                nodeTypes={nodeTypes}
                fitView
                fitViewOptions={{ padding: 0.12, maxZoom: 0.85 }}
                minZoom={0.12}
                maxZoom={1.5}
                nodesDraggable={false}
                nodesConnectable={false}
                onlyRenderVisibleElements
                onNodeClick={(_, n) =>
                  setSelected(
                    query.data.nodes.find((x) => x.id === n.id) || null,
                  )
                }
                onPaneClick={() => setSelected(null)}
                proOptions={{ hideAttribution: false }}
              >
                <Background color="var(--border)" gap={22} size={1} />
                <Controls showInteractive={false} />
              </ReactFlow>
            ) : (
              <Empty title="No relationships in this window">
                Try a longer time range or clear the domain filter.
              </Empty>
            )}
          </Panel>
          <Panel
            className="graph-inspector"
            title={selected ? "Entity details" : "Connection inspector"}
            subtitle={
              selected
                ? selected.kind
                : "Select a node to inspect its neighbors"
            }
          >
            {selected ? (
              <>
                <div className="inspector-identity">
                  <NetworkIcon size={22} />
                  <h3>{selected.label}</h3>
                  <Badge>{connections.length} direct links</Badge>
                </div>
                <div className="connection-list">
                  {connections.slice(0, 40).map((e, i) => {
                    const id = e.source === selected.id ? e.target : e.source;
                    const other = query.data.nodes.find((n) => n.id === id);
                    return (
                      <button
                        key={i}
                        onClick={() => setSelected(other || null)}
                      >
                        <small>{e.relation.replaceAll("_", " ")}</small>
                        <strong>{other?.label || id}</strong>
                        <span>{number(e.count)} observations</span>
                        <time>
                          {e.first_seen} → {e.last_seen} UTC
                        </time>
                      </button>
                    );
                  })}
                </div>
              </>
            ) : (
              <div className="graph-explainer">
                <NetworkIcon size={32} strokeWidth={1} />
                <p>
                  Start with a domain. Follow its aliases, destinations, and the
                  devices requesting it.
                </p>
                <dl>
                  <div>
                    <dt>Pan</dt>
                    <dd>Drag the canvas</dd>
                  </div>
                  <div>
                    <dt>Zoom</dt>
                    <dd>Scroll or use + / −</dd>
                  </div>
                  <div>
                    <dt>Inspect</dt>
                    <dd>Click or focus a node</dd>
                  </div>
                </dl>
              </div>
            )}
          </Panel>
        </div>
      )}
      <p className="footnote">
        Recorded DNS observations, not proof of ownership or application
        identity. Showing {number(query.data?.edges.length)} highest-activity
        connections from up to {number(query.data?.observation_limit || 100000)}
        recent observations{query.data?.truncated ? "; more connections match this view" : ""}.
        Search for a domain or raise the activity threshold to investigate dense
        networks. ASN and country data require a local enrichment file.
      </p>
    </>
  );
}
