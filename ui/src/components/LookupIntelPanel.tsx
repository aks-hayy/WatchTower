import { AlertCircle, Building2, Clock, Globe2, MapPin, Network, Server } from "lucide-react";
import type { IpLookup, LookupPeer, LookupService } from "@/types/watchtower";

function valueOrDash(value: unknown) {
  const text = value === null || value === undefined ? "" : String(value).trim();
  return text && text.toLowerCase() !== "unknown" ? text : "-";
}

function formatBytes(value: number) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = Math.max(0, Number(value || 0));
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatTime(value?: number | null) {
  return value ? new Date(value * 1000).toLocaleString("en-GB") : "-";
}

export function LookupIntelPanel({ lookup }: { lookup: IpLookup }) {
  const identity = lookup.identity || {};
  const endpointIdentity = lookup.endpoint_identity;
  const profile = lookup.asset_profile || {};
  const role = valueOrDash(identity.asset_role || profile.role || identity.device_type);
  const company = valueOrDash(identity.company || identity.organization || lookup.enrichment.org);
  const hostname = valueOrDash(identity.hostname || identity.reverse_dns);

  return (
    <div className="space-y-5">
      <section className="panel p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="section-label section-label-accent">/ IP INTELLIGENCE</div>
            <div className="mt-2 break-all mono text-2xl text-signal">{lookup.ip}</div>
            <div className="mt-1 text-[13px] text-foreground">{hostname}</div>
          </div>
          <div className="shrink-0 border border-border px-2 py-1 mono text-[10px] uppercase text-muted-foreground">
            {lookup.scope} / ipv{lookup.ip_version}
          </div>
        </div>
        <p className="mt-4 text-[13px] leading-relaxed text-muted-foreground">{lookup.summary}</p>
      </section>

      <section className="grid gap-px bg-border md:grid-cols-2 xl:grid-cols-4">
        <Metric label="ROLE" value={role} icon={<Server className="h-3.5 w-3.5" />} />
        <Metric label="ORG / VENDOR" value={company} icon={<Building2 className="h-3.5 w-3.5" />} />
        <Metric
          label="LOCATION"
          value={lookup.location.label}
          icon={<MapPin className="h-3.5 w-3.5" />}
        />
        <Metric
          label="ASN"
          value={valueOrDash(lookup.enrichment.asn)}
          icon={<Globe2 className="h-3.5 w-3.5" />}
        />
      </section>

      {endpointIdentity && (
        <section className="panel">
          <div className="border-b border-border px-4 py-2.5 section-label">/ CAPTURE IDENTITY</div>
          <div className="grid divide-y divide-border md:grid-cols-2 md:divide-x md:divide-y-0">
            <div className="divide-y divide-border">
              <Fact label="Association" value={endpointIdentity.identity_label} />
              <Fact
                label="Classification"
                value={endpointIdentity.identity_type.replaceAll("_", " ")}
              />
            </div>
            <div className="divide-y divide-border">
              <Fact
                label="Evidence State"
                value={`${endpointIdentity.identity_state || "address_only"} / ${Math.round(endpointIdentity.confidence * 100)}% / ${endpointIdentity.verification}`}
              />
              <Fact label="Next Safe Action" value={endpointIdentity.next_action} />
              <Fact
                label="Capture Scope"
                value={`${endpointIdentity.capture_interface || "all interfaces"} / ${endpointIdentity.capture_session_id || endpointIdentity.source || lookup.source}`}
              />
            </div>
          </div>
        </section>
      )}

      <section className="panel">
        <div className="border-b border-border px-4 py-2.5 section-label">
          / ENDPOINT PROCESS EVIDENCE
        </div>
        <div className="divide-y divide-border">
          {(lookup.endpoint_processes || []).slice(0, 8).map((item) => (
            <div key={item.id} className="grid gap-1 px-4 py-3 md:grid-cols-[1fr_auto] md:gap-4">
              <div className="min-w-0">
                <div className="break-all mono text-[11px] text-foreground">
                  {item.image || "Unknown process"}
                  {item.pid ? ` (PID ${item.pid})` : ""}
                </div>
                <div className="mt-1 break-all mono text-[10px] uppercase text-muted-foreground">
                  {(item.service_names || []).join(", ") || "No Windows service mapping"}
                </div>
              </div>
              <div className="mono text-[10px] uppercase text-muted-foreground md:text-right">
                {item.protocol || "-"} / {formatTime(item.observed_at)}
              </div>
            </div>
          ))}
          {(lookup.endpoint_processes || []).length === 0 && (
            <div className="px-4 py-3 text-[12px] text-muted-foreground">
              No Sysmon or endpoint-process evidence is attached to this IP yet.
            </div>
          )}
        </div>
      </section>

      <section className="grid gap-5 xl:grid-cols-2">
        <div className="panel">
          <div className="border-b border-border px-4 py-2.5 section-label">/ IDENTITY</div>
          <div className="divide-y divide-border">
            <Fact label="Hostname" value={identity.hostname} />
            <Fact label="Reverse DNS" value={identity.reverse_dns} />
            <Fact label="MAC" value={identity.mac} />
            <Fact label="Vendor" value={identity.vendor} />
            <Fact label="Device Type" value={identity.device_type} />
            <Fact label="OS" value={identity.os} />
            <Fact label="Source" value={identity.identity_source} />
          </div>
        </div>

        <div className="panel">
          <div className="border-b border-border px-4 py-2.5 section-label">/ ACTIVITY</div>
          <div className="divide-y divide-border">
            <Fact label="Flows" value={lookup.activity.flow_count.toLocaleString("en-US")} />
            <Fact label="Alerts" value={lookup.activity.alert_count.toLocaleString("en-US")} />
            <Fact label="Total Bytes" value={formatBytes(lookup.activity.total_bytes)} />
            <Fact label="Outbound" value={formatBytes(lookup.activity.outbound_bytes)} />
            <Fact label="Inbound" value={formatBytes(lookup.activity.inbound_bytes)} />
            <Fact label="First Seen" value={formatTime(lookup.activity.first_seen)} />
            <Fact label="Last Seen" value={formatTime(lookup.activity.last_seen)} />
          </div>
        </div>
      </section>

      <section className="grid gap-5 xl:grid-cols-2">
        <ListPanel
          title="/ OBSERVED NAMES"
          empty="No DNS, TLS, HTTP, DHCP, NBNS, or reverse-DNS names are attached yet."
          items={lookup.observed_names.slice(0, 10).map((item) => ({
            key: `${item.type}:${item.value}`,
            left: item.value,
            right: item.type,
            sub: item.source,
          }))}
        />
        <ListPanel
          title="/ SERVICES"
          empty="No recognizable service role has been inferred from stored flows."
          items={lookup.services.slice(0, 10).map((item: LookupService) => ({
            key: `${item.direction}:${item.protocol}:${item.port}`,
            left: `${item.name} / ${item.port}`,
            right: item.direction,
            sub: `${item.protocol} / ${Number(item.packets || 0).toLocaleString("en-US")} packets / ${formatBytes(item.bytes)}`,
          }))}
        />
      </section>

      <section className="grid gap-5 xl:grid-cols-2">
        <PeerPanel title="/ INTERNAL PEERS" peers={lookup.peers.internal} />
        <PeerPanel title="/ EXTERNAL PEERS" peers={lookup.peers.external} />
      </section>

      <section className="grid gap-5 xl:grid-cols-2">
        <TextPanel
          title="/ CONTEXT GAPS"
          icon={<AlertCircle className="h-3.5 w-3.5 text-severity-medium" />}
          items={lookup.gaps}
          empty="No major enrichment gaps are known for this IP."
        />
        <TextPanel
          title="/ NEXT ACTIONS"
          icon={<Clock className="h-3.5 w-3.5 text-signal" />}
          items={lookup.next_actions}
          empty="Continue passive monitoring."
        />
      </section>
    </div>
  );
}

function Metric({ label, value, icon }: { label: string; value: string; icon: React.ReactNode }) {
  return (
    <div className="bg-background p-4">
      <div className="flex items-center justify-between section-label">
        <span>{label}</span>
        {icon}
      </div>
      <div className="mt-1 min-h-8 break-words text-[13px] leading-tight text-foreground">
        {value}
      </div>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: unknown }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-3 px-4 py-2.5 text-[12px]">
      <div className="section-label">{label}</div>
      <div className="break-all text-foreground">{valueOrDash(value)}</div>
    </div>
  );
}

function ListPanel({
  title,
  empty,
  items,
}: {
  title: string;
  empty: string;
  items: Array<{ key: string; left: string; right: string; sub: string }>;
}) {
  return (
    <div className="panel">
      <div className="border-b border-border px-4 py-2.5 section-label">{title}</div>
      <div className="divide-y divide-border">
        {items.map((item) => (
          <div key={item.key} className="px-4 py-3">
            <div className="flex items-start justify-between gap-3">
              <div className="break-all text-[12px] text-foreground">{item.left}</div>
              <div className="shrink-0 mono text-[10px] uppercase text-signal">{item.right}</div>
            </div>
            <div className="mt-1 mono text-[10px] uppercase text-muted-foreground">{item.sub}</div>
          </div>
        ))}
        {items.length === 0 && (
          <div className="px-4 py-3 text-[12px] text-muted-foreground">{empty}</div>
        )}
      </div>
    </div>
  );
}

function PeerPanel({ title, peers }: { title: string; peers: LookupPeer[] }) {
  return (
    <div className="panel">
      <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
        <Network className="h-3.5 w-3.5 text-signal" />
        <div className="section-label">{title}</div>
      </div>
      <div className="divide-y divide-border">
        {peers.slice(0, 8).map((peer) => (
          <div key={peer.ip} className="grid grid-cols-[1fr_auto] gap-3 px-4 py-3">
            <div className="break-all mono text-[11px] text-signal">{peer.ip}</div>
            <div className="text-right mono text-[10px] uppercase text-muted-foreground">
              {formatBytes(peer.bytes)} / {Number(peer.packets || 0).toLocaleString("en-US")} pkt
            </div>
          </div>
        ))}
        {peers.length === 0 && (
          <div className="px-4 py-3 text-[12px] text-muted-foreground">No peers in this class.</div>
        )}
      </div>
    </div>
  );
}

function TextPanel({
  title,
  icon,
  items,
  empty,
}: {
  title: string;
  icon: React.ReactNode;
  items: string[];
  empty: string;
}) {
  return (
    <div className="panel">
      <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
        {icon}
        <div className="section-label">{title}</div>
      </div>
      <div className="divide-y divide-border">
        {(items.length ? items : [empty]).map((item, index) => (
          <div
            key={`${item}-${index}`}
            className="px-4 py-3 text-[12px] leading-relaxed text-foreground"
          >
            {item}
          </div>
        ))}
      </div>
    </div>
  );
}
