// Public destinations only. No payment keys, telemetry or remote sponsor scripts.
export const funding = {
  sponsorUrl: "https://github.com/sponsors/Harshil-Anuwadia",
  repositoryUrl: "https://github.com/Harshil-Anuwadia/aegisdns",
  guideUrl:
    "https://github.com/Harshil-Anuwadia/aegisdns/blob/main/SPONSORSHIP.md",
};

export const opportunities = [
  {
    id: "maintenance",
    title: "Maintenance sponsorship",
    description:
      "Help fund maintenance, regression testing, documentation and release work. Recognition is optional; sponsorship does not buy influence over filtering.",
    prompt: "What would your organization like to help maintain?",
  },
  {
    id: "engineering",
    title: "Fund a public improvement",
    description:
      "Commission a scoped integration, packaging improvement or reliability project. Accepted AegisDNS improvements are released under the project’s open-source license.",
    prompt: "Describe the improvement and how you would verify it works.",
  },
  {
    id: "deployment",
    title: "Deployment assistance",
    description:
      "Discuss a paid setup review, migration plan or team handover. The software and installation instructions stay free. Scope, availability and price are agreed before work starts.",
    prompt:
      "Describe the assistance you need, without sharing private network details.",
  },
] as const;
export type Opportunity = (typeof opportunities)[number]["id"];
export function proposalText(
  kind: Opportunity,
  organization: string,
  outcome: string,
  timing: string,
) {
  return `## Organization\n${organization.trim()}\n\n## Interest\n${opportunities.find((o) => o.id === kind)!.title}\n\n## Outcome\n${outcome.trim()}\n\n## Timing\n${timing.trim() || "Flexible"}\n\n## Next step\nPlease discuss scope and availability. This inquiry is not an order or payment authorization. Any engineering engagement needs a separate written agreement. AegisDNS remains free to use.\n`;
}
export function proposalUrl(body: string, kind: Opportunity) {
  const url = new URL(`${funding.repositoryUrl}/issues/new`);
  url.search = new URLSearchParams({
    title: `[Partnership] ${opportunities.find((o) => o.id === kind)!.title}`,
    body,
  }).toString();
  return url.toString();
}
