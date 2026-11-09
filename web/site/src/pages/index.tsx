import { useState } from 'react';
import Link from '@docusaurus/Link';
import { track } from '../lib/analytics'
import useBaseUrl from '@docusaurus/useBaseUrl';
import Layout from '@theme/Layout';
import styles from './index.module.css';

// The interactive request example uses synthetic data only.

interface SpecimenRecord {
  id: string;
  time: string;
  model: string;
  cost: number | null;
  region: string;
  tier: string;
}

const records: SpecimenRecord[] = [
  { id: 'req-004', time: '2026-09-05 14:32', model: 'local-model', cost: null, region: 'Not observed', tier: 'provider_declared' },
  { id: 'req-003', time: '2026-09-05 14:30', model: 'candidate-b', cost: 0.004, region: 'JP', tier: 'header_observed' },
  { id: 'req-002', time: '2026-09-04 16:10', model: 'baseline-a', cost: 0.008, region: 'JP', tier: 'endpoint_pinned' },
  { id: 'req-001', time: '2026-09-04 16:08', model: 'candidate-b', cost: 0.006, region: 'JP', tier: 'provider_attested' },
];

const explanations: Record<string, string> = {
  provider_declared: 'Registered provider default. Actual inference location was not observed.',
  header_observed: 'Response-header signal may identify a CDN edge, not physical inference compute.',
  endpoint_pinned: 'Configured destination is region-pinned. Processing guarantees depend on the provider and endpoint.',
  provider_attested: 'Explicit assertion supplied by the provider integration. A signature alone does not independently confirm physical location.',
};

const periodOptions = [
  { value: 'all', label: 'All example requests' },
  { value: 'latest', label: 'Latest example day' },
  { value: 'empty', label: 'No activity' },
];

function Specimen() {
  const [period, setPeriod] = useState('all');
  const [current, setCurrent] = useState<SpecimenRecord | null>(records[0]);

  const visible =
    period === 'empty' ? [] : period === 'latest' ? records.filter(r => r.time.startsWith('2026-09-05')) : records;
  const priced = visible.filter(r => r.cost !== null);
  const selected = visible.find(r => r.id === current?.id) ?? visible[0] ?? null;
  const scopeText = periodOptions.find(p => p.value === period)?.label ?? 'All example requests';

  return (
    <div className={styles.app}>
      <nav className={styles.sidebar} aria-label="Workspace sections">
        <div className={styles.kicker}>Workspace</div>
        <a href="#requests" aria-current="page">01 / Requests</a>
        <a href="#inspector">02 / Details</a>
        <p>
          Example organization
          <br />
          Sample data · UTC
          <br />
          No production connection
        </p>
      </nav>
      <div className={styles.workspace}>
        <div className={styles.scope}>
          <div>
            <span className={styles.kickerMuted}>Example organization / Sample data</span>
            <h3>Request ledger</h3>
            <p className={styles.scopeText}>Showing: {scopeText} · UTC</p>
          </div>
          <label className={styles.scopeLabel}>
            Time period
            <select
              value={period}
              onChange={e => setPeriod(e.target.value)}
              aria-label="Time period"
            >
              {periodOptions.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </label>
        </div>

        <div className={styles.metrics} aria-live="polite">
          <div className={styles.metric}>
            <span className={styles.metricLabel}>Requests</span>
            <div className={styles.metricValue}>{visible.length}</div>
            <small>In the selected period</small>
          </div>
          <div className={styles.metric}>
            <span className={styles.metricLabel}>Estimated usage cost</span>
            <div className={styles.metricValue}>
              {visible.length && !priced.length ? 'Unknown' : `$${priced.reduce((s, r) => s + (r.cost ?? 0), 0).toFixed(4)}`}
            </div>
            <small>{priced.length} of {visible.length} requests priced</small>
          </div>
          <div className={styles.metric}>
            <span className={styles.metricLabel}>Quality assessment</span>
            <div className={styles.metricValueText}>Not evaluated</div>
            <small>Run an evaluation to compare models</small>
          </div>
        </div>

        <div className={styles.split}>
          <div id="requests">
            <div className={styles.listTitle}>
              <strong>Recent requests</strong>
              <span className={styles.monoMuted}>{visible.length} records</span>
            </div>
            <div className={styles.scroll} tabIndex={0} role="region" aria-label="Requests table, horizontally scrollable on narrow screens">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Request / UTC</th>
                    <th scope="col">Model</th>
                    <th scope="col">Cost, USD</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map(r => (
                    <tr key={r.id} className={selected?.id === r.id ? styles.selected : undefined}>
                      <td>
                        <button type="button" className={styles.rowButton} onClick={() => setCurrent(r)}>{r.id}</button>
                        <div className={styles.monoMuted}>{r.time}</div>
                      </td>
                      <td>{r.model}</td>
                      <td className={styles.mono}>{r.cost === null ? 'Unknown' : r.cost.toFixed(4)}</td>
                    </tr>
                  ))}
                  {!visible.length && (
                    <tr>
                      <td colSpan={3}>No requests in this period.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <p className={styles.notice}>
              <b aria-hidden="true">↳</b>
              <span>Unknown prices are excluded from totals. These example values do not represent a live deployment.</span>
            </p>
          </div>
          <aside className={styles.inspector} id="inspector" aria-label="Selected record" aria-live="polite">
            <span className={styles.kickerMuted}>Selected record</span>
            <h4>{selected ? selected.id : 'No request selected'}</h4>
            <dl className={styles.fields}>
              {selected &&
                ([
                  ['Model', selected.model],
                  ['Recorded region', selected.region],
                  ['Estimated cost', selected.cost === null ? 'Unknown' : `$${selected.cost.toFixed(4)}`],
                  ['Signature', 'Not verified in this example'],
                ] as [string, string][]).map(([name, value]) => (
                  <div key={name}>
                    <dt>{name}</dt>
                    <dd>{value}</dd>
                  </div>
                ))}
            </dl>
            <div className={styles.evidence}>
              <strong>{selected ? selected.tier : 'No location details'}</strong>
              <p>{selected ? explanations[selected.tier] : 'Select a period containing requests.'}</p>
            </div>
          </aside>
        </div>

        <div className={styles.decision}>
          <p>
            <strong>Before changing models:</strong> define a quality baseline. Lower token cost alone is not a deployment decision.
          </p>
          <Link className={styles.decisionLink} to="/docs/audit">Start with the offline audit →</Link>
        </div>
      </div>
    </div>
  );
}

export default function Home() {
  const sampleUrl = useBaseUrl('/examples/audit-sample.html');
  return (
    <Layout wrapperClassName="landing-wrap" title="Self-hosted AI gateway for engineering teams"
      description="Connect supported AI agents to local and approved cloud models. Run Yabanin in your infrastructure to manage access, routing and request logs.">
      <main className={styles.page}>
        <header className={styles.hero}>
          <div>
            <p className={styles.kicker}>A clearer view of AI operations</p>
            <h1>Every request<br />leaves a question.<br /><em>Keep the answer.</em></h1>
            <p className={styles.nameKey}>Yabanin — Your Agnostic Bridge Across Numerous Inference Networks</p>
            <p className={styles.lead}>
              What did it cost? Which model served it? What can you safely change? Run an OpenAI-compatible gateway
              in your environment, start from your own logs, and keep a signed record of each request when lineage is enabled.
            </p>
            <div className={styles.actions}>
              <Link className={styles.primary} to="/docs/quickstart">Get started locally <span aria-hidden="true">↗</span></Link>
              <a className={styles.secondary} href="mailto:sales@yabanin.ai" onClick={() => track('cta_contact', { source: 'hero' })}>Discuss your setup <span aria-hidden="true">→</span></a>
            </div>
            <p className={styles.caption}>Try the local mock setup first, then connect your own provider credentials.</p>
          </div>
          <article className={styles.folio}>
            <div className={styles.folioHead}>
              <span className={styles.kicker}>Field report / 001</span>
              <span className={styles.kickerMuted}>Illustrative workflow</span>
            </div>
            <h2>From a bill<br />to a considered decision.</h2>
            <div className={styles.folioRow}><span className={styles.index}>01</span><div><strong>Read the workload</strong><p>Keep the source local. Expose missing prices and incomplete records.</p></div></div>
            <div className={styles.folioRow}><span className={styles.index}>02</span><div><strong>Test the alternative</strong><p>Compare accepted tasks, cost and latency against an agreed baseline.</p></div></div>
            <div className={styles.folioRow}><span className={styles.index}>03</span><div><strong>Make the change traceable</strong><p>Keep request logs and evaluation results with each routing change.</p></div></div>
            <a className={styles.folioLink} href={sampleUrl}>View a synthetic sample report →</a>
          </article>
        </header>

        <div className={styles.principles}>
          <span><b>01</b>Explicit model routes</span>
          <span><b>02</b>Scoped agent access</span>
          <span><b>03</b>Searchable request logs</span>
        </div>

        <section className={styles.chapter} id="workflow" aria-labelledby="workflow-title">
          <div className={styles.chapterHead}>
            <div>
              <p className={styles.kickerMuted}>One team. One supported workflow.</p>
              <h2 id="workflow-title">Give agents a defined path to your models.</h2>
            </div>
            <p className={styles.chapterNote}>Start with a scoped engineering task. Configure the agent&apos;s model access, keep the request path visible, and review the result against independent acceptance criteria.</p>
          </div>
          <div className={styles.featureGrid}>
            <article><h3>Define the task</h3><p>Agree what a correct result looks like and which data and tools the task may use. Your runner and repository checks own this scope.</p></article>
            <article><h3>Configure the request path</h3><p>Connect a supported client to Yabanin and configure its permitted model routes. Local inference and external providers remain distinct deployment choices.</p></article>
            <article><h3>Review the results</h3><p>Inspect recorded usage and routing decisions. Evaluate the code with your tests and review process before expanding agent access.</p></article>
          </div>
          <p className={styles.caption}>The gateway governs configured requests. It does not replace workspace isolation, code review or release approval.</p>
          <div className={styles.featureGrid} style={{ marginTop: 32 }}>
            <article><h3>Which model actually did the work?</h3><p>Check the recorded execution, not just the model requested by the client. A fallback or routing decision may change the served model.</p></article>
            <article><h3>Which routes are allowed for this workload?</h3><p>Define local and approved external destinations explicitly. Review direct tool and SDK connections separately: a gateway cannot govern traffic that bypasses it.</p></article>
            <article><h3>What did the attempts cost?</h3><p>Include failed requests and retries where records are available. Show missing usage or prices as unknown, not as zero.</p></article>
          </div>
        </section>


        <section className={styles.chapter} id="control" aria-labelledby="control-title">
          <div className={styles.chapterHead}>
            <div>
              <p className={styles.kickerMuted}>A gateway you operate</p>
              <h2 id="control-title">Model access, routing and request logs in one place.</h2>
            </div>
          </div>
          <div className={styles.featureGrid}>
            <article><h3>Scope agent access</h3><p>Use supported agent credentials and grants to define access through the gateway. Review the exact scope and configuration in the agent governance guide.</p><Link to="/docs/agent-governance">Read about agent access →</Link></article>
            <article><h3>Configure model routes</h3><p>Route supported requests to configured providers. Treat fallback rules as part of your data policy, not just an availability setting.</p><Link to="/docs/providers">Review provider integration →</Link></article>
            <article><h3>Inspect request details</h3><p>Review recorded model decisions and usage. When lineage is enabled, a signed record preserves its claim; it does not independently verify the provider's physical compute location.</p><Link to="/docs/lineage">Understand lineage and its limits →</Link></article>
          </div>
        </section>


        <section className={styles.chapter} id="workspace" aria-labelledby="workspace-title">
          <div className={styles.chapterHead}>
            <div>
              <p className={styles.kickerMuted}>Explore an example request</p>
              <h2 id="workspace-title">See how a request was handled.</h2>
            </div>
            <p className={styles.chapterNote}>Select a request to inspect its model, estimated cost and recorded region. The data below is synthetic.</p>
          </div>
          <Specimen />
        </section>


        <section className={styles.chapter} id="measured" aria-labelledby="measured-title">
          <div className={styles.chapterHead}>
            <div>
              <p className={styles.kickerMuted}>Compare models on your workload</p>
              <h2 id="measured-title">Test quality, cost and latency together.</h2>
            </div>
            <p className={styles.chapterNote}>Use representative tasks and expected results to compare routes before changing production traffic. A cheaper response is useful only if it meets your requirements.</p>
          </div>
          <div className={styles.featureGrid}>
            <article><h3>Choose representative tasks</h3><p>Include common requests, tool calls and failure cases. Keep a separate set of tasks for checking changes.</p></article>
            <article><h3>Compare results</h3><p>Check answer quality alongside latency, token usage and estimated cost. Include retries and missing prices in your analysis.</p></article>
            <article><h3>Roll out gradually</h3><p>Review routing and guard evaluation results, then monitor request logs as you expand traffic.</p><Link to="/docs/evaluation">Run routing and guard evaluations →</Link></article>
          </div>
        </section>


        <section className={styles.chapter} id="deploy" aria-labelledby="deploy-title">
          <div className={styles.chapterHead}>
            <div>
              <p className={styles.kickerMuted}>Deployment choices</p>
              <h2 id="deploy-title">Keep deployment and data routes explicit.</h2>
            </div>
            <p className={styles.chapterNote}>Running the gateway yourself gives you an operating boundary. Where inference runs depends on the model endpoints you configure.</p>
          </div>
          <div className={styles.deployGrid}>
            <article>
              <span className={styles.badge}>Local-only configuration</span>
              <h3>Local models for restricted workloads</h3>
              <p>Use local inference when the workload must stay inside your chosen environment. Verify network rules and the full dependency chain, including tools, telemetry, logs and backups.</p>
              <Link to="/docs/onprem/airgap-checklist">Review the air-gap checklist →</Link>
            </article>
            <article>
              <span className={styles.badge}>Approved-cloud configuration</span>
              <h3>External models where your policy permits</h3>
              <p>Operate Yabanin in your VPC or on premises and configure approved external inference routes. Review provider terms and data settings for each enabled service and feature.</p>
              <Link to="/docs/onprem/install-guide" onClick={() => track('cta_deploy_docs', { source: 'deploy' })}>Plan your deployment →</Link>
            </article>
          </div>
          <p className={styles.caption}>Self-hosting the gateway does not make external inference local. Both configurations require secure installation and ongoing operation.</p>
        </section>


        <section className={styles.chapter} id="technical-fit" aria-labelledby="technical-fit-title">
          <div className={styles.chapterHead}>
            <div>
              <p className={styles.kickerMuted}>Check the technical fit</p>
              <h2 id="technical-fit-title">Start with the client and workflow you actually use.</h2>
            </div>
            <p className={styles.chapterNote}>Verify the client&apos;s API, streaming and tool requirements before connecting it. Provider support and client compatibility are different questions; an upstream adapter does not imply support for every inbound API.</p>
          </div>
          <Link className={styles.primary} to="/docs/providers">Review supported provider integration <span aria-hidden="true">→</span></Link>
        </section>


        <section className={styles.chapter} id="audit" aria-labelledby="audit-title">
          <div className={styles.chapterHead}>
            <div>
              <p className={styles.kickerMuted}>Your first useful result</p>
              <h2 id="audit-title">Bring a log.<br />Get a clearer picture.</h2>
            </div>
            <p className={styles.chapterNote}>The audit reads JSONL or CSV locally and produces a shareable report: spend concentration, data-quality gaps, cache and routing simulated separately.</p>
          </div>
          <div className={styles.auditGrid}>
            <div className={styles.terminal}>
              <div className={styles.terminalTitle}><span aria-hidden="true">● ● ●</span> LOCAL TERMINAL</div>
              <pre><code>{`yb audit traffic.jsonl \\
  --cache-mode exact \\
  --format html \\
  --output report.html \\
  --no-prompts`}</code></pre>
            </div>
            <div className={styles.auditSide}>
              <div className={styles.folioRow}><span className={styles.index}>01</span><div><strong>Spend breakdown</strong><p>Recorded usage plus pricing, with missing prices clearly marked.</p></div></div>
              <div className={styles.folioRow}><span className={styles.index}>02</span><div><strong>Cache &amp; routing</strong><p>Simulated separately. Savings depend on your traffic; simulations do not establish answer quality.</p></div></div>
              <Link className={styles.primary} to="/docs/audit">Read the audit guide <span aria-hidden="true">↗</span></Link>
            </div>
          </div>
        </section>


        <section className={styles.close} id="talk">
          <p className={styles.kickerMuted}>Start with one workflow</p>
          <h2>Put your next agent rollout<br />on a defined path.</h2>
          <p className={styles.chapterNote}>Tell us which agent you use, where it must run, and what a correct result looks like. We can discuss a scoped pilot around your deployment and acceptance requirements. Start with a description of the workflow. Do not send source code, secrets or raw prompts in your first message.</p>
          <div className={styles.actions}>
            <a className={styles.primary} href="mailto:sales@yabanin.ai" onClick={() => track('cta_contact', { source: 'footer' })}>Discuss your agent setup <span aria-hidden="true">→</span></a>
            <Link className={styles.secondary} to="/docs/demo" onClick={() => track('cta_explore_audit', { source: 'footer' })}>Run the local demo →</Link>
          </div>
          <p className={styles.chapterNote}>Core is available under Apache-2.0. See LICENSE and LICENSING.md in the source repository for license and brand terms.</p>
        </section>
 

     </main>
    </Layout>
  );
}
