import { useState } from "react";
import { Code2, Plus, Trash2, Workflow } from "lucide-react";
import { send, time, useApi } from "../api";
import type { Action, ActionLog } from "../types";
import {
  AsyncForm,
  Badge,
  Button,
  ConfirmButton,
  Dialog,
  Empty,
  ErrorState,
  Field,
  PageHeader,
  Panel,
  Skeleton,
  Table,
} from "../components/ui";

export default function Actions() {
  const actions = useApi<Action[]>("/actions"),
    logs = useApi<ActionLog[]>("/actions/logs", 15000),
    [open, setOpen] = useState(false),
    [edit, setEdit] = useState<Action | null>(null);
  return (
    <>
      <PageHeader
        eyebrow="INFRASTRUCTURE / CUSTOM ACTIONS"
        title="Small actions. Local control."
        description="Manage authenticated local endpoints for webhooks, approved commands, and HTML responses."
        action={
          <Button
            variant="primary"
            onClick={() => {
              setEdit(null);
              setOpen(true);
            }}
          >
            <Plus size={16} />
            Create action
          </Button>
        }
      />
      {actions.error ? (
        <ErrorState
          error={actions.error}
          retry={() => void actions.refetch()}
        />
      ) : !actions.data ? (
        <Skeleton />
      ) : !actions.data.length ? (
        <Panel>
          <Empty title="No custom actions">
            Create a local endpoint when you need an authenticated network
            action.
          </Empty>
        </Panel>
      ) : (
        <div className="source-list">
          {actions.data.map((a) => (
            <Panel key={a.domain}>
              <div className="source-row">
                <Workflow size={24} className="muted" />
                <div className="source-name">
                  <h2>{a.domain}</h2>
                  <span>
                    {a.payload_url ||
                      (a.action_type === "shell"
                        ? "Approved executable"
                        : "Sandboxed HTML response")}
                  </span>
                </div>
                <Badge>{a.action_type}</Badge>
                <Button
                  onClick={() => {
                    setEdit(a);
                    setOpen(true);
                  }}
                >
                  Edit
                </Button>
                <ConfirmButton
                  title="Delete custom action?"
                  description={`Remove the authenticated endpoint for ${a.domain}.`}
                  onConfirm={() =>
                    send(
                      `/actions/${encodeURIComponent(a.domain)}`,
                      undefined,
                      "DELETE",
                    )
                  }
                >
                  <Trash2 size={16} />
                  <span className="sr-only">Delete {a.domain}</span>
                </ConfirmButton>
              </div>
            </Panel>
          ))}
        </div>
      )}
      <div className="section-gap" />
      <Panel
        title="Execution history"
        subtitle="The latest recorded action runs"
        action={
          <ConfirmButton
            title="Clear action history?"
            description="Permanently delete all custom-action execution logs."
            onConfirm={() => send("/actions/logs", undefined, "DELETE")}
          >
            Clear history
          </ConfirmButton>
        }
      >
        {logs.error ? (
          <ErrorState error={logs.error} />
        ) : !logs.data ? (
          <Skeleton />
        ) : !logs.data.length ? (
          <Empty title="No executions recorded" />
        ) : (
          <Table headers={["Timestamp", "Domain", "Result", "Message"]}>
            {logs.data.map((l, i) => (
              <tr key={l.id || i}>
                <td className="mono">{time(l.triggered_at)}</td>
                <td>{l.domain}</td>
                <td>
                  <Badge tone={l.outcome === "success" ? "success" : "danger"}>
                    {l.outcome}
                  </Badge>
                </td>
                <td>{l.detail || "—"}</td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
      <p className="footnote">
        DNS queries never execute actions. The action listener accepts
        authenticated POST requests on port 5381.
      </p>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title={edit ? "Edit action" : "Create an action"}
        description="Use a local .root, .aegis, .lan, or .home.arpa domain."
      >
        {open && <ActionForm initial={edit} close={() => setOpen(false)} />}
      </Dialog>
    </>
  );
}
function ActionForm({
  initial,
  close,
}: {
  initial: Action | null;
  close: () => void;
}) {
  const [kind, setKind] = useState(initial?.action_type || "webhook"),
    [html, setHtml] = useState(initial?.html_content || ""),
    [fileError, setFileError] = useState("");
  return (
    <AsyncForm
      label="Save action"
      onSuccess={close}
      submit={(d) =>
        send("/actions", {
          domain: String(d.get("domain")).trim(),
          action_type: kind,
          payload_url: kind === "webhook" ? d.get("url") : null,
          method: kind === "webhook" ? d.get("method") : null,
          shell_command: kind === "shell" ? d.get("command") : null,
          html_content: kind === "html" ? html : null,
          success_msg: d.get("success"),
          token: d.get("token"),
        })
      }
    >
      <Field label="Local domain">
        <input
          name="domain"
          required
          defaultValue={initial?.domain}
          readOnly={!!initial}
          placeholder="desk.lan"
        />
      </Field>
      <Field label="Action type">
        <select value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="webhook">HTTPS webhook</option>
          <option value="shell">Approved executable</option>
          <option value="html">HTML response</option>
        </select>
      </Field>
      {kind === "webhook" && (
        <>
          <Field label="Webhook URL">
            <input
              type="url"
              name="url"
              pattern="https://.*"
              required
              defaultValue={initial?.payload_url || ""}
              placeholder="https://example.com/hook"
            />
          </Field>
          <Field label="Method">
            <select name="method" defaultValue={initial?.method || "POST"}>
              <option>POST</option>
              <option>GET</option>
            </select>
          </Field>
        </>
      )}
      {kind === "shell" && (
        <Field
          label="Argument array"
          hint="The executable must be an absolute path permitted by AEGIS_ACTION_EXECUTABLES."
        >
          <textarea
            className="mono"
            name="command"
            required
            defaultValue={initial?.shell_command || ""}
            placeholder={'["/usr/local/bin/job", "{value}"]'}
          />
        </Field>
      )}
      {kind === "html" && (
        <>
          <Field label="HTML response">
            <textarea
              className="mono"
              value={html}
              onChange={(e) => setHtml(e.target.value)}
              rows={7}
            />
          </Field>
          <Field label="Import HTML file">
            <input
              type="file"
              accept=".html,.htm,text/html"
              onChange={async (e) => {
                const file = e.target.files?.[0];
                if (!file) return;
                if (file.size > 128 * 1024) {
                  setFileError("Use an HTML file smaller than 128 KB.");
                  return;
                }
                try {
                  setHtml(await file.text());
                  setFileError("");
                } catch {
                  setFileError("The file could not be read.");
                }
              }}
            />
          </Field>
          {fileError && (
            <p className="form-error" role="alert">
              {fileError}
            </p>
          )}
        </>
      )}
      <Field label="Success message">
        <input
          name="success"
          defaultValue={initial?.success_msg || ""}
          placeholder="Action completed"
        />
      </Field>
      <Field
        label={initial ? "Replacement bearer token" : "Bearer token"}
        hint="32–256 characters. Keep a copy securely; the token is not shown again."
      >
        <input
          type="password"
          name="token"
          minLength={32}
          maxLength={256}
          required
          autoComplete="new-password"
        />
      </Field>
    </AsyncForm>
  );
}
