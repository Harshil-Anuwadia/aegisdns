import { useState } from "react";
import { ArrowUpRight, Download, HeartHandshake } from "lucide-react";
import { Button, Field, PageHeader, Panel } from "../components/ui";
import {
  funding,
  opportunities,
  proposalText,
  proposalUrl,
  type Opportunity,
} from "../funding";

export default function Support() {
  const [kind, setKind] = useState<Opportunity>("maintenance");
  const [organization, setOrganization] = useState(""),
    [outcome, setOutcome] = useState(""),
    [timing, setTiming] = useState("");
  const [draft, setDraft] = useState<{ body: string; url: string } | null>(
    null,
  );
  const [downloadError, setDownloadError] = useState("");
  function download() {
    if (!draft) return;
    try {
      const url = URL.createObjectURL(
        new Blob([draft.body], { type: "text/markdown;charset=utf-8" }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = "aegisdns-partnership.md";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setDownloadError("");
    } catch {
      setDownloadError(
        "The download could not start. You can copy the draft below.",
      );
    }
  }
  return (
    <>
      <PageHeader
        eyebrow="PROJECT / FUNDING"
        title="Keep AegisDNS independent."
        description="Free to download, self-host, modify and use. Funding supports the work behind it."
      />
      <div className="settings-layout funding-layout">
        <div>
          <Panel
            title="Sponsor the maintainer"
            subtitle="Optional support, through GitHub Sponsors"
          >
            <div className="panel-body funding-intro">
              <p>
                AegisDNS is maintained by Harshil Anuwadia. A one-time or
                recurring contribution helps pay for development time, testing
                and maintenance.
              </p>
              <a
                className="button primary"
                href={funding.sponsorUrl}
                target="_blank"
                rel="noopener noreferrer"
              >
                Sponsor on GitHub <ArrowUpRight size={16} />
              </a>
              <p className="footnote">
                Choose an amount and review payment terms on GitHub. You never
                need to sponsor to use AegisDNS.
              </p>
            </div>
          </Panel>
          <div className="section-gap" />
          <Panel
            title="For organizations"
            subtitle="Fund work that everyone can use"
          >
            <div className="funding-opportunities">
              {opportunities.map((o) => (
                <article key={o.id}>
                  <h3>{o.title}</h3>
                  <p>{o.description}</p>
                </article>
              ))}
            </div>
          </Panel>
        </div>
        <aside className="settings-aside funding-principles">
          <HeartHandshake size={30} strokeWidth={1.4} />
          <h2>The same software for everyone.</h2>
          <p>
            Funding adds no feature locks, device limits or subscription
            requirement. AegisDNS remains MIT licensed.
          </p>
          <h2>Your DNS stays out of it.</h2>
          <p>
            This page sends no query history, device inventory or network
            configuration to sponsors. It contains no advertising scripts,
            tracking pixels or automatic calls to payment services.
          </p>
          <h2>Other ways to help</h2>
          <p>
            Reproducible bug reports, documentation, testing on your hardware
            and telling another self-hoster about AegisDNS all help.
          </p>
          <a
            className="text-link"
            href={funding.repositoryUrl}
            target="_blank"
            rel="noopener noreferrer"
          >
            Visit the project <ArrowUpRight size={15} />
          </a>
        </aside>
      </div>
      <div className="section-gap" />
      <Panel
        title="Start a partnership conversation"
        subtitle="Prepare a short inquiry, then review it before sharing"
      >
        <div className="panel-body">
          <form
            className="form funding-form"
            onChange={() => setDraft(null)}
            onSubmit={(e) => {
              e.preventDefault();
              const body = proposalText(kind, organization, outcome, timing);
              setDraft({ body, url: proposalUrl(body, kind) });
            }}
          >
            <fieldset>
              <div className="form-grid">
                <Field label="Interested in">
                  <select
                    value={kind}
                    onChange={(e) => setKind(e.target.value as Opportunity)}
                  >
                    {opportunities.map((o) => (
                      <option key={o.id} value={o.id}>
                        {o.title}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Organization">
                  <input
                    required
                    maxLength={100}
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    placeholder="Organization or team name"
                  />
                </Field>
              </div>
              <Field
                label="What would you like to accomplish?"
                hint={opportunities.find((o) => o.id === kind)!.prompt}
              >
                <textarea
                  required
                  minLength={10}
                  maxLength={600}
                  rows={4}
                  value={outcome}
                  onChange={(e) => setOutcome(e.target.value)}
                />
              </Field>
              <Field label="Preferred timing (optional)">
                <input
                  maxLength={100}
                  value={timing}
                  onChange={(e) => setTiming(e.target.value)}
                  placeholder="For example, next quarter"
                />
              </Field>
              <p className="note">
                Drafts stay in this browser until you choose to share them.
                GitHub issues are public: omit credentials, DNS logs, private
                infrastructure and billing details.
              </p>
            </fieldset>
            <div className="form-footer">
              <span>No message is sent automatically.</span>
              <Button type="submit" variant="primary">
                Prepare inquiry
              </Button>
            </div>
          </form>
          {draft && (
            <section className="funding-draft" aria-label="Inquiry draft">
              <h3>Your inquiry is ready to review</h3>
              <Field label="Draft text">
                <textarea readOnly rows={12} value={draft.body} />
              </Field>
              <div className="funding-draft-actions">
                <a
                  className="button primary"
                  href={draft.url}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Review draft on GitHub <ArrowUpRight size={16} />
                </a>
                <Button onClick={download}>
                  <Download size={16} />
                  Download draft
                </Button>
              </div>
              <p className="footnote">
                GitHub opens a public issue draft. Sign in, review it, and
                submit only when ready. Preparing an inquiry does not reserve
                work or authorize payment.
              </p>
              {downloadError && (
                <p role="alert" className="form-error">
                  {downloadError}
                </p>
              )}
            </section>
          )}
        </div>
      </Panel>
    </>
  );
}
