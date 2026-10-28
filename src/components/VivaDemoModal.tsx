import React, { useState } from 'react';
import { useCrisp } from '../context/CrispContext';
import {
  Sparkles,
  X,
  ChevronRight,
  ChevronLeft,
  Shield,
  Radio,
  ShieldAlert,
  Flame,
  GitMerge,
  Calculator,
  Award,
  BrainCircuit,
  Wrench,
  Clock,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  Database,
  ArrowRight,
  Play,
  RotateCcw,
} from 'lucide-react';

interface VivaDemoModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface DemoStep {
  stepNumber: number;
  title: string;
  duration: string;
  tabTarget: string;
  subTabTarget?: string;
  icon: React.ElementType;
  narrativeHeadline: string;
  talkTrack: string;
  keyPoints: string[];
  vivaQuestionHook: string;
  examinerInsight: string;
}

export const VivaDemoModal: React.FC<VivaDemoModalProps> = ({ isOpen, onClose }) => {
  const { setActiveTab, setSubTab } = useCrisp();
  const [currentStep, setCurrentStep] = useState(0);

  const DEMO_STEPS: DemoStep[] = [
    {
      stepNumber: 1,
      title: 'Executive Posture & Risk Overview',
      duration: '1.0 min',
      tabTarget: 'overview',
      icon: Shield,
      narrativeHeadline: 'Holistic Enterprise Cyber Risk Posture at a Glance',
      talkTrack:
        'Start your presentation by demonstrating the high-level executive dashboard. Explain how CRISP synthesizes raw vulnerabilities, real-time threat telemetry, asset criticality tiers, and NIST CSF 2.0 compliance into an authoritative single-pane-of-glass risk index.',
      keyPoints: [
        'Enterprise Risk Score (0–100 scale) with dynamic tier gauge',
        'Breakdown of mission-critical, high, medium, and low assets',
        'NIST CSF 2.0 6-function compliance radar',
        'Real-time alert tally: CISA KEV weaponized bugs vs live anomalies',
      ],
      vivaQuestionHook:
        '"Why not simply rely on CVSS scores alone?" -> Explain that CVSS only measures intrinsic technical severity without organizational context (asset criticality, external exposure, active exploitation, or frequency).',
      examinerInsight: 'Demonstrates enterprise architecture and executive decision-making support.',
    },
    {
      stepNumber: 2,
      title: 'Real NVD Vulnerability Intelligence',
      duration: '1.0 min',
      tabTarget: 'intelligence',
      subTabTarget: 'vulnerabilities',
      icon: ShieldAlert,
      narrativeHeadline: '1,750+ Authoritative Real NVD CVEs with Zero Mock Data',
      talkTrack:
        'Navigate to the Vulnerabilities catalog to show authentic CVE records imported from the NIST NVD 2.0 API. Highlight real CVSS 3.1 base vectors, CWE weakness enumerations, affected vendor products, and reference advisories.',
      keyPoints: [
        '1,753 real CVEs stored in embedded SQLite database',
        'CVSS 3.1 vector string decomposition (AV, AC, PR, UI, S, C, I, A)',
        'Full-text search by CVE ID, vendor, or affected product (e.g., Log4j, OpenSSH, Ivanti)',
        'Zero data fabrication policy: all metadata originates from NIST',
      ],
      vivaQuestionHook:
        '"How do you handle NVD API rate limits and upstream outages?" -> Point out the server-side proxy cache with 10-minute TTL, exponential backoff, and local curated catalog fallback.',
      examinerInsight: 'Demonstrates robust external API engineering and real data provenance.',
    },
    {
      stepNumber: 3,
      title: 'CISA KEV Weaponization Status',
      duration: '1.0 min',
      tabTarget: 'intelligence',
      subTabTarget: 'cisa_kev',
      icon: Flame,
      narrativeHeadline: 'Active In-The-Wild Exploitation Intelligence (BOD 22-01)',
      talkTrack:
        'Switch to the CISA KEV view. Show that vulnerabilities actively weaponized by threat actors receive urgent priority and strict mandatory remediation due dates per federal Binding Operational Directives.',
      keyPoints: [
        'Authoritative feed from CISA Known Exploited Vulnerabilities catalog',
        'Identifies ransomware campaign utilization (e.g., LockBit, Cl0p)',
        'Tracks required action and compliance due dates with overdue alerts',
        'Instantly escalates CRISP risk scoring by +15 points',
      ],
      vivaQuestionHook:
        '"What is the difference between a high CVSS vulnerability and a CISA KEV vulnerability?" -> 90% of CVEs are never exploited in the wild. CISA KEV represents confirmed active weaponization.',
      examinerInsight: 'Shows threat-informed defense and regulatory compliance adherence.',
    },
    {
      stepNumber: 4,
      title: 'Historical Telemetry & Controlled Simulator',
      duration: '1.5 min',
      tabTarget: 'live',
      icon: Radio,
      narrativeHeadline: 'Real Benchmark Telemetry (CIC-IDS2017) vs Clearly Labeled Simulation',
      talkTrack:
        'Open Live Monitoring. Show historical intrusion detection records imported from the University of New Brunswick CIC-IDS2017 dataset. Then activate the controlled simulation generator to illustrate real-time attack detection.',
      keyPoints: [
        'CIC-IDS2017 benchmark dataset with PortScan, SSH-BruteForce, Web Attacks, and DoS',
        'Strict ethical labeling: simulation events are explicitly tagged with "[SIMULATION MODE]"',
        'Interactive simulation controls: adjustable event frequency (1s to 5s)',
        'Ingestion queue with backpressure regulation and dead-letter queue (DLQ)',
      ],
      vivaQuestionHook:
        '"How do you prevent simulated events from polluting production intelligence?" -> Show the `is_real_data` flag and `dataset_source` database columns with separate audit trails.',
      examinerInsight: 'Proves ethical engineering integrity and streaming telemetry capabilities.',
    },
    {
      stepNumber: 5,
      title: 'Multi-Entity Finding Correlation',
      duration: '1.0 min',
      tabTarget: 'intelligence',
      subTabTarget: 'findings',
      icon: GitMerge,
      narrativeHeadline: 'Deterministic Triangulation of Telemetry + Vulnerabilities + Assets',
      talkTrack:
        'Demonstrate the Correlation Engine. Explain how CRISP matches disparate data points: an incoming brute-force/exploit event on IP 10.0.4.15 is triangulated with affected asset AST-PROD-WEB-01 and CVE-2021-44228.',
      keyPoints: [
        'Deterministic correlation graph avoiding speculative AI hallucinations',
        'Attributes external attack sources to specific enterprise internal targets',
        'Identifies affected services, protocols, ports, and software versions',
        'Generates persistent Correlated Findings stored with unique finding IDs',
      ],
      vivaQuestionHook:
        '"Why not use an LLM for event correlation?" -> LLMs are non-deterministic and can hallucinate associations. CRISP uses a deterministic rule-based correlation engine, reserving LLMs for reasoning and explanation.',
      examinerInsight: 'Shows solid systems design and security architecture maturity.',
    },
    {
      stepNumber: 6,
      title: 'Explainable CRISP Multi-Factor Risk Score',
      duration: '1.0 min',
      tabTarget: 'intelligence',
      subTabTarget: 'risk_matrix',
      icon: Calculator,
      narrativeHeadline: 'Transparent 6-Factor Mathematical Risk Formulation (0–100)',
      talkTrack:
        'Open the Cyber Risk Matrix. Walk through the explainable mathematical model that computes residual cyber risk: CVSS (30%), CISA KEV (15%), Asset Criticality (15%), Perimeter Exposure (15%), Attack Frequency (15%), and Recency (10%).',
      keyPoints: [
        'Zero black-box scoring: full breakdown modal with point contributions and rationale',
        'Asset Criticality: Mission-Critical (14/15 pts) vs Internal Low (2/15 pts)',
        'Perimeter Exposure: External Internet (12–15 pts) vs Air-Gapped (1 pt)',
        'Live recalculation engine evaluates over 36,000 operations per second',
      ],
      vivaQuestionHook:
        '"Is this an official NIST formula?" -> Emphasize the clear disclaimer: CRISP uses an explainable composite multi-factor formula inspired by NIST CSF risk assessment principles, not an official NIST standard formula.',
      examinerInsight: 'Demonstrates rigorous quantitative modeling and algorithmic transparency.',
    },
    {
      stepNumber: 7,
      title: 'Supervised Multi-Agent Swarm (LangGraph)',
      duration: '2.0 min',
      tabTarget: 'swarm',
      icon: BrainCircuit,
      narrativeHeadline: '7 Specialized Domain Agents Coordinated by a Central Supervisor',
      talkTrack:
        'Navigate to the AI Swarm. Run a live investigation on Log4Shell on AST-PROD-WEB-01. Show real-time streaming output as the Orchestrator delegates concurrent tasks to Threat Intel, Vuln Intel, Asset Risk, Compliance, and Evidence agents.',
      keyPoints: [
        'Supervised hierarchical orchestration inspired by LangGraph state machines',
        'Strict role-based agent specialization: read-only access prevents unintended execution',
        'Concurrent agent execution via Python ThreadPoolExecutor with bounded timeouts',
        'Resilience: if Groq is offline, deterministic heuristic fallback produces full valid reports',
      ],
      vivaQuestionHook:
        '"What prevents prompt injection from turning agents malicious?" -> Highlight `detect_prompt_injection()`, read-only safety controls, input sanitization, and strict separation of passive document data.',
      examinerInsight: 'Demonstrates state-of-the-art agentic AI architecture and defensive engineering.',
    },
    {
      stepNumber: 8,
      title: 'RAG Evidence Retrieval & Verification',
      duration: '1.0 min',
      tabTarget: 'swarm',
      icon: Database,
      narrativeHeadline: 'ChromaDB Vector Knowledge Bases with Fact Verification Guardrails',
      talkTrack:
        'Show the Evidence and Verification agent cards. Point out how documents retrieved via ChromaDB vector collections (vulnerabilities, NIST controls, assets, findings) are cross-checked by the VerificationAgent to catch hallucinations and contradictions.',
      keyPoints: [
        'Multi-collection ChromaDB vector storage with cosine similarity search',
        'VerificationAgent strictly separates confirmed facts, derived hypotheses, and missing data',
        'Automatic contradiction detection (e.g., CVSS 9.8 marked as LOW severity)',
        'Zero-hallucination return message: "No relevant CRISP data was found"',
      ],
      vivaQuestionHook:
        '"How do you measure verification confidence?" -> Explain the dynamic confidence score (e.g. 98% for confirmed findings vs 40% when critical telemetry evidence is missing).',
      examinerInsight: 'Validates academic rigor in AI safety and RAG evaluation.',
    },
    {
      stepNumber: 9,
      title: 'NIST CSF 2.0 Governance & Compliance',
      duration: '1.0 min',
      tabTarget: 'intelligence',
      subTabTarget: 'compliance',
      icon: Award,
      narrativeHeadline: '6-Function Governance Mapping (GOVERN through RECOVER)',
      talkTrack:
        'Open the NIST CSF 2.0 view. Explain how the platform evaluates security controls against the newly updated NIST Cybersecurity Framework 2.0 standard, highlighting gaps and remediation requirements.',
      keyPoints: [
        'Complete coverage of 6 Core Functions: GV, ID, PR, DE, RS, RC',
        'Real-time compliance percentage with automated deficiency scoring',
        'Correlates unresolved findings with specific control violations (e.g., PR.DS-01, DE.CM-01)',
        'Provides executive audit readiness metrics for compliance officers',
      ],
      vivaQuestionHook:
        '"What changed in NIST CSF 2.0 compared to 1.1?" -> NIST 2.0 introduced the "GOVERN" (GV) function, emphasizing cyber risk governance as an enterprise-wide responsibility.',
      examinerInsight: 'Shows deep comprehension of regulatory and compliance frameworks.',
    },
    {
      stepNumber: 10,
      title: 'Closed-Loop Remediation & Risk Reassessment',
      duration: '1.5 min',
      tabTarget: 'intelligence',
      subTabTarget: 'remediation',
      icon: Wrench,
      narrativeHeadline: 'From Verified Findings to Scan Verification & Risk Reduction',
      talkTrack:
        'Conclude with the Remediation Queue. Show the full lifecycle: Generating a structured plan, role-based approval by Security Lead, submitting Tenable/Nessus verification evidence, and automatically observing risk score drop from 88.5 to 41.5.',
      keyPoints: [
        'Lifecycle: OPEN -> PLANNED -> AWAITING_APPROVAL -> IN_PROGRESS -> AWAITING_VERIFICATION -> RESOLVED',
        'Mandatory authentic verification evidence (clean scan or SBOM package version)',
        'Automatic plan reopening if scan detects persisting vulnerability',
        'Dynamic residual risk recalculation: demonstrates measurable ROI of security action',
      ],
      vivaQuestionHook:
        '"Can an analyst mark a task resolved without evidence?" -> Absolutely not. The system enforces zero-trust resolution; attempting to resolve without evidence raises an authorization error.',
      examinerInsight: 'Demonstrates full closed-loop remediation engineering and SOC operations mastery.',
    },
  ];

  if (!isOpen) return null;

  const activeStepData = DEMO_STEPS[currentStep];
  const StepIcon = activeStepData.icon;

  const handleNavigateToFeature = () => {
    setActiveTab(activeStepData.tabTarget);
    if (activeStepData.subTabTarget) {
      setSubTab(activeStepData.subTabTarget);
    }
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-4xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-md shadow-cyan-500/20 text-white font-bold">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-white tracking-tight">
                  CRISP 2.0 — Final Viva Demonstration Script
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/80">
                  8–12 Min Workflow
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Step-by-step academic walkthrough with talk tracks, key points, and examiner defense Q&amp;A
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Progress Stepper Bar */}
        <div className="px-6 py-2.5 bg-slate-950/60 border-b border-slate-800/80 overflow-x-auto flex items-center gap-1.5">
          {DEMO_STEPS.map((step, idx) => (
            <button
              key={step.stepNumber}
              onClick={() => setCurrentStep(idx)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-semibold transition-all shrink-0 ${
                currentStep === idx
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 shadow-sm'
                  : idx < currentStep
                  ? 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800'
                  : 'text-slate-500 hover:text-slate-300 border border-transparent'
              }`}
            >
              <span className="font-mono text-[10px]">{step.stepNumber}.</span>
              <span className="truncate max-w-[100px]">{step.title.split(' ')[0]}</span>
              {idx < currentStep && <CheckCircle2 className="w-3 h-3 text-emerald-400" />}
            </button>
          ))}
        </div>

        {/* Body Content */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-slate-200">
          {/* Headline & Overview */}
          <div className="flex items-start justify-between gap-4 p-4 rounded-xl bg-slate-950/80 border border-slate-800">
            <div className="flex items-center gap-3.5">
              <div className="w-11 h-11 rounded-xl bg-cyan-950 text-cyan-400 border border-cyan-800/80 flex items-center justify-center shrink-0">
                <StepIcon className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-cyan-400 font-bold uppercase tracking-wider">
                    Stage {activeStepData.stepNumber} of 10 ({activeStepData.duration})
                  </span>
                </div>
                <h3 className="text-base font-bold text-white tracking-tight mt-0.5">
                  {activeStepData.title}
                </h3>
                <p className="text-xs text-slate-300 mt-0.5">
                  {activeStepData.narrativeHeadline}
                </p>
              </div>
            </div>

            <button
              onClick={handleNavigateToFeature}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-md shadow-cyan-600/20 transition-all shrink-0"
            >
              <span>Take Me There</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Talk Track */}
          <div className="space-y-2">
            <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" />
              <span>Suggested Presenter Talk Track</span>
            </h4>
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800/90 text-slate-200 text-xs leading-relaxed italic">
              &ldquo;{activeStepData.talkTrack}&rdquo;
            </div>
          </div>

          {/* Key Demonstrable Capabilities */}
          <div className="space-y-2">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
              Key Architecture &amp; Implementation Highlights
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {activeStepData.keyPoints.map((pt, i) => (
                <div
                  key={i}
                  className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs text-slate-300"
                >
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{pt}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Viva Defense & Examiner Hook */}
          <div className="p-4 rounded-xl bg-indigo-950/30 border border-indigo-800/60 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-indigo-300 font-mono uppercase tracking-wider flex items-center gap-1.5">
                <BrainCircuit className="w-3.5 h-3.5" />
                <span>Expected Viva Examiner Question &amp; Defense</span>
              </span>
              <span className="text-[10px] font-mono text-indigo-400 bg-indigo-950 px-2 py-0.5 rounded border border-indigo-800/80">
                Defensive Readiness
              </span>
            </div>
            <p className="text-xs text-indigo-200/90 leading-relaxed font-sans">
              {activeStepData.vivaQuestionHook}
            </p>
            <div className="text-[11px] text-slate-400 pt-1 border-t border-indigo-900/40">
              <span className="text-slate-300 font-semibold">Examiner Impression:</span>{' '}
              {activeStepData.examinerInsight}
            </div>
          </div>
        </div>

        {/* Footer Navigation */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-950 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
              disabled={currentStep === 0}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-xs font-semibold text-slate-300 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
              <span>Previous</span>
            </button>
            <button
              onClick={() => setCurrentStep(Math.min(DEMO_STEPS.length - 1, currentStep + 1))}
              disabled={currentStep === DEMO_STEPS.length - 1}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-xs font-semibold text-slate-300 transition-colors"
            >
              <span>Next Stage</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-400 font-mono">
              Step {currentStep + 1} of {DEMO_STEPS.length}
            </span>
            <button
              onClick={handleNavigateToFeature}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors shadow-sm"
            >
              <span>Open Feature in CRISP</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
