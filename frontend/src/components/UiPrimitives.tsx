import { useState, type ReactNode } from "react";

export function StatusBadge({
  label,
  tone = "neutral",
}: {
  label: string;
  tone?: "running" | "success" | "danger" | "neutral";
}) {
  return <span className={`status-badge status-badge-${tone}`}>{label}</span>;
}

export function PanelHeader({
  title,
  subtitle,
  icon,
  rightSlot,
}: {
  title: string;
  subtitle?: string;
  icon?: string;
  rightSlot?: ReactNode;
}) {
  return (
    <div className="card-header">
      <div className="flex items-center gap-2">
        {icon && <span className="text-base">{icon}</span>}
        <div>
          <div className="card-title">{title}</div>
          {subtitle ? <div className="card-subtitle">{subtitle}</div> : null}
        </div>
      </div>
      {rightSlot}
    </div>
  );
}

export function CodeDisclosure({
  label,
  value,
  initialOpen = false,
}: {
  label: string;
  value: string;
  initialOpen?: boolean;
}) {
  const [open, setOpen] = useState(initialOpen);

  return (
    <div className="code-disclosure">
      <button className="code-disclosure-trigger" onClick={() => setOpen((v) => !v)}>
        <span>{label}</span>
        <span>{open ? "收起" : "展开"}</span>
      </button>
      {open ? <pre className="code-block">{value}</pre> : null}
    </div>
  );
}

export function EventSummary({
  title,
  detail,
  tone = "neutral",
}: {
  title: string;
  detail?: string;
  tone?: "neutral" | "result";
}) {
  return (
    <div className={`event-row event-row-${tone}`}>
      <div className="event-row-title">{title}</div>
      {detail ? <div className="event-row-detail">{detail}</div> : null}
    </div>
  );
}
