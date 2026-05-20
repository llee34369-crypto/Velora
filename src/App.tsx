import React, { useState, useEffect, useRef } from "react";
// @ts-ignore
import logoUrl from "./assets/images/velora_logo_black_1779284603876.png";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Search,
  Code2,
  Globe,
  Terminal,
  ArrowRight,
  Lock,
  Unlock,
  Sliders,
  Send,
  RefreshCw,
  Eye,
  BookOpen,
  Sparkles,
  Zap,
  Info,
  ChevronDown,
  ChevronUp,
  Cpu,
  FileCode,
  ExternalLink,
  Download
} from "lucide-react";
import { CONTRACT_TEMPLATES, ContractTemplate } from "./data";
import {
  AuditReport,
  Vulnerability,
  GasOptimization,
  WebsiteScanReport,
  VulnerabilitySeverity
} from "./types";

export default function App() {
  const [activeTab, setActiveTab] = useState<"contracts" | "websites" | "chat">("contracts");
  
  // App Notification State
  const [apiError, setApiError] = useState<string | null>(null);

  // Smart Contract Scanner State
  const [contractCode, setContractCode] = useState<string>(CONTRACT_TEMPLATES[0].code);
  const [selectedTemplate, setSelectedTemplate] = useState<number>(0);
  const [checks, setChecks] = useState<string[]>([
    "Reentrancy",
    "Access Control Bypass",
    "Integer Overflow / Underflow",
    "Flash Loan Attacks",
    "Signature Malleability",
    "Insecure tx.origin Usage"
  ]);
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [auditStep, setAuditStep] = useState<string>("");
  const [auditProgress, setAuditProgress] = useState<number>(0);
  const [auditReport, setAuditReport] = useState<AuditReport | null>(null);
  const [vulnFilter, setVulnFilter] = useState<string>("All");
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null);

  // Website Scanner State
  const [targetUrl, setTargetUrl] = useState<string>("uniswap.org");
  const [isScanningUrl, setIsScanningUrl] = useState<boolean>(false);
  const [scanReport, setScanReport] = useState<WebsiteScanReport | null>(null);
  const [selectedScanContract, setSelectedScanContract] = useState<number | null>(null);
  const [showConnectedReportDetails, setShowConnectedReportDetails] = useState<boolean>(false);

  // SecOps Chat State
  const [chatInput, setChatInput] = useState<string>("");
  const [isChatLoading, setIsChatLoading] = useState<boolean>(false);
  const [messages, setMessages] = useState<Array<{ role: "user" | "assistant"; content: string }>>([
    {
      role: "assistant",
      content:
        "Greetings. I am Velora, your expert Web3 & Cryptographic SecOps Specialist. Ask me any question regarding smart contract audit standards, known attack vectors, gas efficiency tricks, or frontend interaction security."
    }
  ]);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  // Automatically scroll chat to bottom when message content shifts
  useEffect(() => {
    if (chatBottomRef.current) {
      chatBottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, isChatLoading]);

  // Load preset template
  const handleSelectTemplate = (index: number) => {
    setSelectedTemplate(index);
    setContractCode(CONTRACT_TEMPLATES[index].code);
  };

  // Toggle checklist parameters
  const toggleCheck = (check: string) => {
    if (checks.includes(check)) {
      setChecks(checks.filter((c) => c !== check));
    } else {
      setChecks([...checks, check]);
    }
  };

  // Run the Smart Contract Audit
  const handleRunAudit = async () => {
    if (!contractCode.trim()) {
      setApiError("Please provide some Solidity contract code to audit.");
      return;
    }
    setApiError(null);
    setIsAuditing(true);
    setAuditReport(null);
    setVulnFilter("All");
    setExpandedVuln(null);

    // Dynamic audit sequence visualizer
    const steps = [
      { msg: "Mapping abstract syntax trees (AST)...", progress: 15 },
      { msg: "Running state variables taint analysis...", progress: 38 },
      { msg: "Inspecting Checks-Effects-Interactions flows...", progress: 60 },
      { msg: "Running EVM symbolic execution solvers...", progress: 82 },
      { msg: "Compiling detailed threat vector matrix...", progress: 95 }
    ];

    for (const step of steps) {
      setAuditStep(step.msg);
      setAuditProgress(step.progress);
      await new Promise((resolve) => setTimeout(resolve, 800));
    }

    try {
      const response = await fetch("/api/audit-contract", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ contractCode, checks })
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.details || "The secure audit container failed to initialize.");
      }

      const reportData: AuditReport = await response.json();
      setAuditReport(reportData);
    } catch (err: any) {
      console.error(err);
      setApiError(
        err.message ||
          "An unexpected error occurred during state audit. Ensure GEMINI_API_KEY is properly loaded."
      );
    } finally {
      setIsAuditing(false);
    }
  };

  // Run the Website Frontend Scan
  const handleRunUrlScan = async () => {
    if (!targetUrl.trim()) {
      setApiError("Please provide a valid website URL to audit.");
      return;
    }
    setApiError(null);
    setIsScanningUrl(true);
    setScanReport(null);
    setSelectedScanContract(null);

    try {
      const response = await fetch("/api/scan-website", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl })
      });

      if (!response.ok) {
        throw new Error("Target connection timed out or blocked by destination firewall.");
      }

      const scanResult: WebsiteScanReport = await response.json();
      setScanReport(scanResult);
    } catch (err: any) {
      console.error(err);
      setApiError(err.message || "Failed to establish proxy handshake with domain provider.");
    } finally {
      setIsScanningUrl(false);
    }
  };

  // Download high-fidelity security audit markdown report
  const handleDownloadMarkdown = () => {
    if (!auditReport) return;
    const templateName = CONTRACT_TEMPLATES[selectedTemplate]?.name || "Custom Smart Contract";

    let md = `# VELORA WEB3 SECURITY SUITE - AUDIT REPORT
==================================================
Target Module : ${templateName}
Timestamp     : ${new Date().toUTCString()}
Security Score: ${auditReport.securityScore}/100

--------------------------------------------------

## 1. EXECUTIVE SUMMARY
${auditReport.summary}

--------------------------------------------------

## 2. DETECTED ATTACK PROFILE Findings (${auditReport.vulnerabilities.length} issues)

`;

    auditReport.vulnerabilities.forEach((v) => {
      md += `### [${v.id}] ${v.title} (${v.severity.toUpperCase()})
- **Location:** Line ${v.lineNumber}
- **Vulnerability Brief:** ${v.description}
- **Proof-of-Concept Trajectory:** ${v.proofOfConcept}

#### Target Vulnerable Segment:
\`\`\`solidity
${v.codeSnippet}
\`\`\`

#### Remediation Instructions:
\`\`\`solidity
${v.remediation}
\`\`\`

--------------------------------------------------
`;
    });

    if (auditReport.gasOptimizations && auditReport.gasOptimizations.length > 0) {
      md += `

## 3. GAS OPTIMIZATION DIRECTIVES (${auditReport.gasOptimizations.length} directives)

`;
      auditReport.gasOptimizations.forEach((gas, index) => {
        md += `### GAS-[0${index + 1}] ${gas.title}
- **Description:** ${gas.description}
- **Optimized Recommendation Snippet:**
\`\`\`solidity
${gas.remediation}
\`\`\`

--------------------------------------------------
`;
      });
    }

    md += `\n*Disclaimer: This report was compiled dynamically using Velora's cryptographic static analysis module and Gemini's Deep Web3 Reasoning Core.*`;

    const blob = new Blob([md], { type: "text/markdown;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `velora-security-dossier-${templateName.toLowerCase().replace(/\s+/g, "-")}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Download high-fidelity frontend scan markdown report
  const handleDownloadWebsiteScanReport = () => {
    if (!scanReport) return;

    let md = `# VELORA WEB3 SECURITY SUITE - DAPP FRONTEND SCAN REPORT
==================================================
Target Domain    : ${scanReport.url}
Timestamp        : ${new Date().toUTCString()}
Security Rating  : ${scanReport.securityScore}/100
Overall Verdict  : ${scanReport.verdict?.toUpperCase()}
SSL Verification : ${scanReport.isHttps ? "PASSED (HTTPS Enabled)" : "FAILED (Insecure HTTP)"}
Response Time    : ${scanReport.responseTimeMs} ms

--------------------------------------------------

## 1. HOST INFRASTRUCTURE PARAMETERS
- **Server Signature:** ${scanReport.headers?.server || "N/A"}
- **X-Powered-By Framework:** ${scanReport.headers?.xPoweredBy || "N/A"}
- **Content-Type MIME:** ${scanReport.headers?.contentType || "N/A"}
- **Cache Control:** ${scanReport.headers?.cacheControl || "N/A"}

--------------------------------------------------

## 2. HTTP SECURITY HEADERS ASSESSMENT
`;

    scanReport.headerAssessments?.forEach((assessment) => {
      md += `### [${assessment.present ? "PASS" : "MISSING"}] ${assessment.name} (${assessment.header})
- **Severity If Missing:** ${assessment.severity || "N/A"}
- **Current Value:** ${assessment.present ? assessment.value : "None"}
- **Recommendation:** ${assessment.recommendation}

`;
    });

    md += `--------------------------------------------------

## 3. WEB3 CONTEXT & SCRIPT DIAGNOSTICS
- **Wagmi Library Usage:** ${scanReport.web3Indicators?.usesWagmi ? "Detected" : "Not Detected"}
- **Ethers.js Client:** ${scanReport.web3Indicators?.usesEthers ? "Detected" : "Not Detected"}
- **MetaMask Providers:** ${scanReport.web3Indicators?.usesMetamaskIndicator ? "Detected" : "Not Detected"}
- **WalletConnect API:** ${scanReport.web3Indicators?.usesWalletConnect ? "Detected" : "Not Detected"}

`;

    if (scanReport.web3Indicators?.insecureExternalScripts && scanReport.web3Indicators.insecureExternalScripts.length > 0) {
      md += `### UNSECURED EXTERNAL SCRIPT BUNDLES DETECTED:
`;
      scanReport.web3Indicators.insecureExternalScripts.forEach((script) => {
        md += `- ${script}\n`;
      });
      md += `\n`;
    }

    if (scanReport.connectedContracts && scanReport.connectedContracts.length > 0) {
      md += `--------------------------------------------------

## 4. DETECTED ECOSYSTEM SMART CONTRACTS (${scanReport.connectedContracts.length})
`;
      scanReport.connectedContracts.forEach((contract) => {
        const score = contract.auditReport?.securityScore || 100;
        md += `### ${contract.name} (${contract.type.toUpperCase()})
- **Address:** ${contract.address}
- **Network:** ${contract.network}
- **Security Score:** ${score}/100
`;
      });
    }

    md += `\n*Disclaimer: This report was compiled dynamically using Velora's cryptographic static analysis module and Gemini's Deep Web3 Reasoning Core.*`;

    const blob = new Blob([md], { type: "text/markdown;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    const sanitizedDomain = scanReport.url.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase();
    link.setAttribute("download", `velora-frontend-dossier-${sanitizedDomain}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Download connected smart contract audit report
  const handleDownloadConnectedContractReport = (cIdx: number) => {
    if (!scanReport || !scanReport.connectedContracts || !scanReport.connectedContracts[cIdx]) return;
    const contract = scanReport.connectedContracts[cIdx];
    const report = contract.auditReport;
    if (!report) return;

    let md = `# VELORA WEB3 SECURITY SUITE - CONNECTED SMART CONTRACT AUDIT REPORT
==================================================
Target Contract: ${contract.name}
Contract Type  : ${contract.type.toUpperCase()}
EVM Address    : ${contract.address}
Network        : ${contract.network}
Timestamp      : ${new Date().toUTCString()}
Security Score : ${report.securityScore}/100

--------------------------------------------------

## 1. EXECUTIVE DETAILED BRIEFING
${report.summary}

--------------------------------------------------

## 2. DETECTED ATTACK TRAJECTORIES (${report.vulnerabilities.length} findings)

`;

    report.vulnerabilities.forEach((v) => {
      md += `### [${v.id}] ${v.title} (${v.severity.toUpperCase()})
- **Approximate Location:** Line ${v.lineNumber}
- **Details:** ${v.description}
- **Exploitation Scenario:** ${v.proofOfConcept}

#### Vulnerable Code Segment:
\`\`\`solidity
${v.codeSnippet}
\`\`\`

#### Proposed Remediation:
\`\`\`solidity
${v.remediation}
\`\`\`

--------------------------------------------------
`;
    });

    if (report.gasOptimizations && report.gasOptimizations.length > 0) {
      md += `
## 3. GAS PERFORMANCE CRITERIA (${report.gasOptimizations.length} directives)

`;
      report.gasOptimizations.forEach((gas, index) => {
        md += `### GAS-[0${index + 1}] ${gas.title}
- **Description:** ${gas.description}
- **Target Optimized Snippet:**
\`\`\`solidity
${gas.remediation}
\`\`\`

--------------------------------------------------
`;
      });
    }

    md += `\n*Disclaimer: This report was compiled dynamically using Velora's cryptographic static analysis module and Gemini's Deep Web3 Reasoning Core.*`;

    const blob = new Blob([md], { type: "text/markdown;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    const sanitizedName = contract.name.replace(/\s+/g, "-").toLowerCase();
    link.setAttribute("download", `velora-connected-contract-${sanitizedName}-${contract.address.slice(0, 8)}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Send message to Velora Chatbot
  const handleSendMessage = async (customText?: string) => {
    const textToSend = customText || chatInput;
    if (!textToSend.trim()) return;

    if (!customText) setChatInput("");
    setApiError(null);

    // Update locally before API starts
    const updatedMessages = [
      ...messages,
      { role: "user" as const, content: textToSend }
    ];
    setMessages(updatedMessages);
    setIsChatLoading(true);

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: updatedMessages })
      });

      if (!response.ok) {
        throw new Error("Chat container failed to resolve current query state.");
      }

      const resData = await response.json();
      setMessages([
        ...updatedMessages,
        { role: "assistant" as const, content: resData.reply }
      ]);
    } catch (err: any) {
      setApiError(err.message || "Chat prompt gateway disconnected. Verify server log diagnostics.");
    } finally {
      setIsChatLoading(false);
    }
  };

  // Filter vulnerabilities list
  const filteredVulns = auditReport?.vulnerabilities.filter((v) => {
    if (vulnFilter === "All") return true;
    return v.severity === vulnFilter;
  }) || [];

  // Get score color
  const getScoreColor = (score: number) => {
    if (score >= 85) return "text-emerald-500 hover:text-emerald-400 border-emerald-500/20";
    if (score >= 60) return "text-yellow-500 hover:text-yellow-400 border-yellow-500/20";
    return "text-red-500 hover:text-red-400 border-red-500/30";
  };

  const getScoreBg = (score: number) => {
    if (score >= 85) return "bg-emerald-950/20 text-emerald-400";
    if (score >= 60) return "bg-yellow-950/20 text-yellow-400";
    return "bg-red-950/20 text-red-400";
  };

  // Get severity border color classes for active/expanded states
  const getSeverityBorderColorClass = (severity: VulnerabilitySeverity) => {
    switch (severity) {
      case "Critical":
        return "border-red-500/40 ring-1 ring-red-500/10 bg-red-950/5";
      case "High":
        return "border-orange-500/40 ring-1 ring-orange-500/10 bg-orange-950/5";
      case "Medium":
        return "border-yellow-500/40 ring-1 ring-yellow-500/10 bg-yellow-950/5";
      case "Low":
        return "border-blue-500/40 ring-1 ring-blue-500/10 bg-blue-950/5";
      case "Informational":
        return "border-zinc-700 ring-1 ring-zinc-700/10 bg-zinc-900/5";
    }
  };

  // Get severity color classes
  const getSeverityBadgeClass = (severity: VulnerabilitySeverity) => {
    switch (severity) {
      case "Critical":
        return "bg-red-500/15 text-red-400 border border-red-500/30 font-semibold";
      case "High":
        return "bg-orange-500/15 text-orange-400 border border-orange-500/30 font-medium";
      case "Medium":
        return "bg-yellow-500/15 text-yellow-400 border border-yellow-500/20";
      case "Low":
        return "bg-blue-500/15 text-blue-400 border border-blue-500/20";
      case "Informational":
        return "bg-zinc-800 text-zinc-300 border border-zinc-700";
    }
  };

  return (
    <div className="min-h-screen bg-black text-zinc-100 flex flex-col font-sans selection:bg-lime-500/30 selection:text-lime-300 relative overflow-hidden">
      
      {/* Visual Identity Decorator Elements (Ambient Radial Glows) */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[300px] bg-gradient-to-r from-emerald-500/8 to-lime-500/8 blur-[120px] rounded-full pointer-events-none z-0" />
      <div className="absolute top-[350px] right-24 w-[350px] h-[350px] bg-emerald-500/4 blur-[130px] rounded-full pointer-events-none z-0" />
      <div className="absolute bottom-20 left-20 w-[400px] h-[400px] bg-lime-500/4 blur-[140px] rounded-full pointer-events-none z-0" />

      {/* HEADER SECTION */}
      <header className="border-b border-zinc-900/80 bg-black/70 backdrop-blur-md sticky top-0 z-20 relative">
        <div className="max-w-7xl mx-auto px-4 py-3.5 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-20 h-20 select-none flex items-center justify-center bg-black rounded-2xl p-1 shrink-0 transition-all duration-300 hover:scale-105 shadow-xl shadow-lime-500/5 hover:shadow-lime-500/10 border border-zinc-900">
              <img
                src={logoUrl}
                alt="Velora Logo"
                className="w-full h-full object-contain"
                referrerPolicy="no-referrer"
              />
            </div>
            <div>
              <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2.5">
                Velora <span className="text-zinc-700 font-light text-base">/</span> 
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-lime-300 text-xs font-bold uppercase tracking-widest bg-emerald-950/20 px-2.5 py-1 rounded-full border border-emerald-500/15 shadow-sm">Web3 Auditor</span>
              </h1>
              <p className="text-xs text-zinc-400 mt-1 max-w-md">High-fidelity cryptographic audits & decentralized vulnerability detection suite</p>
            </div>
          </div>

          <div className="flex items-center bg-[#070707] p-1 rounded-xl border border-zinc-800/60 gap-1 relative z-10">
            <button
              onClick={() => setActiveTab("contracts")}
              className={`px-3.5 py-2 text-xs font-medium rounded-lg transition-all duration-200 flex items-center gap-2 ${
                activeTab === "contracts"
                  ? "bg-zinc-900 border border-emerald-500/25 text-[#a3e635] shadow-sm font-semibold"
                  : "text-zinc-400 hover:text-zinc-200 border border-transparent"
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              Contract Audit
            </button>
            <button
              onClick={() => setActiveTab("websites")}
              className={`px-3.5 py-2 text-xs font-medium rounded-lg transition-all duration-200 flex items-center gap-2 ${
                activeTab === "websites"
                  ? "bg-zinc-900 border border-emerald-500/25 text-[#a3e635] shadow-sm font-semibold"
                  : "text-zinc-400 hover:text-zinc-200 border border-transparent"
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              dApp Frontend Scan
            </button>
            <button
              onClick={() => setActiveTab("chat")}
              className={`px-3.5 py-2 text-xs font-medium rounded-lg transition-all duration-200 flex items-center gap-2 ${
                activeTab === "chat"
                  ? "bg-zinc-900 border border-emerald-500/25 text-[#a3e635] shadow-sm font-semibold"
                  : "text-zinc-400 hover:text-zinc-200 border border-transparent"
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              SecOps Chat Expert
            </button>
          </div>
        </div>
      </header>

      {/* GLOBAL NOTIFICATIONS / KEYS GUIDE */}
      {apiError && (
        <div className="bg-red-950/50 border-y border-red-500/20 py-2.5 px-4 text-center text-xs text-red-300 flex items-center justify-center gap-2 animate-fade-in">
          <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
          <span>{apiError}</span>
          <button
            onClick={() => setApiError(null)}
            className="ml-3 hover:text-white bg-red-900/40 px-2 py-0.5 rounded text-[10px] uppercase border border-red-500/20"
          >
            Acknowledge
          </button>
        </div>
      )}

      {/* MAIN LAYOUT */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 flex flex-col gap-6">

        {/* 1. CONTRACTS AUDIT ENGINE */}
        {activeTab === "contracts" && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            
            {/* Control Sidebar */}
            <div className="lg:col-span-4 flex flex-col gap-6">
              
              {/* Presets Card */}
              <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-5 flex flex-col gap-3">
                <div className="flex items-center gap-2 border-b border-zinc-800 pb-2.5">
                  <BookOpen className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-white">Vulnerable Presets</h3>
                </div>
                <p className="text-xs text-zinc-400 leading-relaxed mb-1">
                  Load a standard vulnerable contract template to witness live, exact diagnostic scans and remediation reports instantly.
                </p>
                <div className="flex flex-col gap-2">
                  {CONTRACT_TEMPLATES.map((tmpl, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleSelectTemplate(idx)}
                      className={`text-left p-2.5 rounded-lg text-xs leading-relaxed transition flex flex-col gap-0.5 border ${
                        selectedTemplate === idx
                          ? "bg-zinc-800/80 border-emerald-500/30 text-emerald-300"
                          : "bg-zinc-950 hover:bg-zinc-800/30 border-zinc-900 text-zinc-400 hover:text-zinc-200"
                      }`}
                    >
                      <span className="font-medium text-white flex items-center gap-1.5">
                        <FileCode className="w-3.5 h-3.5 text-zinc-400" />
                        {tmpl.name}
                      </span>
                      <span className="text-[11px] text-zinc-500 truncate max-w-full">
                        {tmpl.description}
                      </span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Scanning Parameters Checklist */}
              <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-5 flex flex-col gap-3">
                <div className="flex items-center gap-2 border-b border-zinc-800 pb-2.5">
                  <Sliders className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-white">Auditing Directives</h3>
                </div>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  Select key blockchain attack profiles to direct Velora’s static analysis module during code traversal.
                </p>
                
                <div className="flex flex-col gap-2 mt-2">
                  {[
                    "Reentrancy",
                    "Access Control Bypass",
                    "Integer Overflow / Underflow",
                    "Flash Loan Attacks",
                    "Signature Malleability",
                    "Insecure tx.origin Usage",
                    "Uninitialized Proxy Storage",
                    "Front running risks"
                  ].map((checkName) => (
                    <label
                      key={checkName}
                      className="flex items-center gap-2.5 p-2 rounded bg-zinc-950/40 hover:bg-zinc-950 border border-zinc-900/60 transition cursor-pointer select-none text-[11px]"
                    >
                      <input
                        type="checkbox"
                        checked={checks.includes(checkName)}
                        onChange={() => toggleCheck(checkName)}
                        className="rounded border-zinc-700 text-emerald-500 bg-zinc-900 focus:ring-opacity-0 w-3.5 h-3.5"
                      />
                      <span className={checks.includes(checkName) ? "text-white font-medium" : "text-zinc-500"}>
                        {checkName}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            </div>

            {/* Main Code & Output Panel */}
            <div className="lg:col-span-8 flex flex-col gap-6">
              
              {/* Code Inputs Box */}
              <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-5 flex flex-col gap-3">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    <h3 className="text-sm font-semibold text-white">Solidity Interactive Console</h3>
                  </div>
                  <span className="text-[10px] bg-emerald-950/50 text-emerald-400 border border-emerald-500/10 px-2 py-0.5 rounded font-mono uppercase tracking-wider">
                    Solidity v0.8.x + Safe
                  </span>
                </div>
                
                <div className="relative">
                  <textarea
                    value={contractCode}
                    onChange={(e) => setContractCode(e.target.value)}
                    placeholder="// Paste your Solidity Smart Contract code here..."
                    className="w-full h-80 bg-zinc-950 font-mono text-xs p-4 rounded-xl border border-zinc-800 text-zinc-300 focus:outline-none focus:ring-1 focus:ring-emerald-500/40 leading-relaxed resize-none cursor-text"
                    spellCheck={false}
                  />
                  {isAuditing && (
                    <div className="absolute inset-0 bg-zinc-950/90 rounded-xl flex flex-col items-center justify-center p-8 text-center animate-fade-in">
                      <div className="relative w-16 h-16 mb-4">
                        <div className="absolute inset-x-0 inset-y-0 rounded-full border-2 border-zinc-800 border-t-emerald-500 animate-spin" />
                        <div className="absolute inset-x-2 inset-y-2 rounded-full border-2 border-zinc-800 border-b-emerald-400 animate-spin-reverse" />
                        <Shield className="absolute inset-x-0 inset-y-0 m-auto text-emerald-400 w-5 h-5" />
                      </div>
                      
                      <div className="text-xs font-semibold text-white tracking-wider uppercase mb-1">
                        Analyzing Bytecode Trajectories
                      </div>
                      <div className="text-[11px] text-zinc-500 font-mono max-w-sm tracking-tight truncate mb-3">
                        {auditStep}
                      </div>

                      {/* Progress bar */}
                      <div className="w-48 bg-zinc-900 h-1.5 rounded-full overflow-hidden border border-zinc-800">
                        <div 
                          className="bg-emerald-500 h-full transition-all duration-300 rounded-full" 
                          style={{ width: `${auditProgress}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>

                <div className="flex justify-end mt-1">
                  <button
                    onClick={handleRunAudit}
                    disabled={isAuditing}
                    className="px-6 py-2.5 bg-gradient-to-r from-emerald-500 to-lime-400 hover:from-emerald-400 hover:to-lime-300 disabled:from-zinc-800 disabled:to-zinc-850 disabled:bg-zinc-800 text-black font-bold rounded-lg text-xs leading-none uppercase tracking-widest transition-all duration-300 flex items-center gap-2 cursor-pointer shadow-lg shadow-emerald-500/10 disabled:text-zinc-600 disabled:cursor-not-allowed"
                  >
                    <Zap className="w-4 h-4 fill-current shrink-0" />
                    Launch Diagnostic Scan
                  </button>
                </div>
              </div>

              {/* AUDIT REPORT REPORT CARDS */}
              {auditReport && (
                <div id="velora-audit-report-container" className="flex flex-col gap-6 animate-fade-in relative z-10">
                  
                  {/* Premium Action Bar with Download Button */}
                  <div id="velora-action-banner" className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-gradient-to-r from-emerald-950/25 to-lime-950/15 border border-emerald-500/15 rounded-2xl p-5 shadow-xl backdrop-blur-sm">
                    <div>
                      <span className="text-[10px] font-mono tracking-widest uppercase text-[#a3e635] font-semibold block mb-0.5">Static Analysis Compiled</span>
                      <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                        Velora High-Fidelity Security Dossier
                      </h3>
                      <p className="text-[11px] text-zinc-500">Ready for cryptosecurity validation and on-chain protocol deployment</p>
                    </div>
                    
                    <button
                      id="download-md-report-btn"
                      onClick={handleDownloadMarkdown}
                      className="inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-emerald-500 to-lime-400 hover:from-emerald-400 hover:to-lime-300 text-black font-bold text-xs uppercase tracking-widest rounded-xl transition-all duration-300 shadow-md shadow-emerald-500/10 hover:shadow-emerald-400/20 active:scale-98 cursor-pointer border border-emerald-400/20 shrink-0"
                    >
                      <Download className="w-4 h-4" />
                      Download Report (.MD)
                    </button>
                  </div>
                  
                  {/* High Level Dossier Summary */}
                  <div id="velora-summary-dossier" className="grid grid-cols-1 md:grid-cols-12 gap-5 bg-[#0e0e0e]/90 rounded-2xl border border-zinc-800/80 p-6 items-center shadow-lg">
                    
                    {/* Score Dial Circle */}
                    <div className="md:col-span-4 flex flex-col items-center justify-center text-center py-2 border-r border-zinc-800/50 md:border-r md:pr-4">
                      <div className="relative w-32 h-32 flex items-center justify-center">
                        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                          {/* Background Track */}
                          <circle
                            cx="50"
                            cy="50"
                            r="42"
                            className="stroke-zinc-900 fill-none"
                            strokeWidth="8"
                          />
                          {/* Score Fill Track */}
                          <circle
                            cx="50"
                            cy="50"
                            r="42"
                            className={`fill-none transition-all duration-1000 ${
                              auditReport.securityScore >= 85
                                ? "stroke-emerald-500"
                                : auditReport.securityScore >= 60
                                ? "stroke-yellow-500"
                                : "stroke-red-500"
                            }`}
                            strokeWidth="8"
                            strokeDasharray="264"
                            strokeDashoffset={264 - (264 * auditReport.securityScore) / 100}
                            strokeLinecap="round"
                          />
                        </svg>
                        <div className="absolute flex flex-col items-center select-none">
                          <span className="text-4xl font-black text-white tracking-tight bg-gradient-to-tr from-white to-zinc-400 bg-clip-text text-transparent">
                            {auditReport.securityScore}
                          </span>
                          <span className="text-[9px] text-zinc-500 uppercase tracking-widest font-mono">
                            SCORE
                          </span>
                        </div>
                      </div>
                      
                      <div className="mt-4 px-3 py-1.5 rounded-full text-[10px] font-mono tracking-widest uppercase font-semibold bg-black border border-zinc-800/80">
                        {auditReport.securityScore >= 85 ? (
                          <span className="text-emerald-400 flex items-center gap-1">● Class-A Verified</span>
                        ) : auditReport.securityScore >= 60 ? (
                          <span className="text-yellow-400 flex items-center gap-1">● Class-C Warning</span>
                        ) : (
                          <span className="text-red-400 flex items-center gap-1">🔑 Class-F Critical</span>
                        )}
                      </div>
                    </div>

                    {/* Quick Stats Summary */}
                    <div className="md:col-span-8 flex flex-col gap-3">
                      <div className="flex items-center gap-1.5 text-[#a3e635] font-mono text-xs">
                        <Shield className="w-3.5 h-3.5" />
                        VELORA_PROTOCOL_DIAGNOSTIC
                      </div>
                      <h4 className="text-sm font-semibold text-white tracking-tight">System Threat Landscape Summary</h4>
                      <p className="text-xs text-zinc-400 leading-relaxed font-sans">
                        {auditReport.summary}
                      </p>

                      {/* Diagnostic badges overview */}
                      <div className="grid grid-cols-5 gap-2 mt-2">
                        {["Critical", "High", "Medium", "Low", "Informational"].map((sev) => {
                          const count = auditReport.vulnerabilities.filter((v) => v.severity === sev).length;
                          return (
                            <button
                              key={sev}
                              onClick={() => setVulnFilter(vulnFilter === sev ? "All" : sev)}
                              className={`p-2 rounded-xl flex flex-col items-center justify-center border text-center transition-all duration-200 ${
                                vulnFilter === sev
                                  ? "bg-gradient-to-r from-emerald-500/10 to-lime-500/10 border-emerald-500/40 text-emerald-300 font-bold scale-[1.03]"
                                  : count === 0
                                  ? "bg-black/50 border-zinc-900 text-zinc-650 hover:text-zinc-500"
                                  : "bg-black hover:bg-zinc-900 border-zinc-800 text-zinc-300 hover:border-zinc-700"
                              }`}
                            >
                              <span className="text-xs font-bold leading-none">{count}</span>
                              <span className="text-[9px] uppercase tracking-wide text-zinc-500 mt-1">{sev.slice(0, 4)}</span>
                            </button>
                          );
                        })}
                      </div>
                    </div>

                    {/* Vulnerabilities Quick Index Table/List */}
                    <div className="md:col-span-12 border-t border-zinc-900 pt-5 mt-2 flex flex-col gap-3">
                      <div className="flex items-center justify-between border-b border-zinc-800/60 pb-2">
                        <span className="text-[11px] font-mono uppercase tracking-widest text-[#a3e635] font-semibold flex items-center gap-1.5 animate-pulse">
                          <Sliders className="w-3.5 h-3.5 text-[#a3e635]" />
                          Vulnerability Threats Index
                        </span>
                        <span className="text-[10px] text-zinc-500 font-mono">
                          Clicking "View Report" expands and scrolls to details
                        </span>
                      </div>
                      
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {auditReport.vulnerabilities.map((vuln) => (
                          <div 
                            key={`index-${vuln.id}`}
                            className="bg-zinc-950 hover:bg-zinc-900/60 border border-zinc-900/90 hover:border-zinc-800/80 rounded-xl p-3.5 flex items-center justify-between gap-4 transition duration-300 text-left group"
                          >
                            <div className="flex items-center gap-3 min-w-0">
                              <span className="font-mono text-[10px] text-[#a3e635] bg-zinc-900 px-2 py-1 rounded border border-zinc-850 shrink-0 font-bold group-hover:bg-[#a3e635] group-hover:text-black transition">
                                {vuln.id}
                              </span>
                              <div className="flex flex-col min-w-0">
                                <span className="font-bold text-xs text-white tracking-wide truncate group-hover:text-[#a3e635] transition duration-200">
                                  {vuln.title}
                                </span>
                                <span className="text-[10px] text-zinc-500 font-mono mt-1 flex items-center gap-1.5 flex-wrap">
                                  Line <span className="text-zinc-300 font-bold">{vuln.lineNumber}</span> 
                                  <span className="text-zinc-700 font-sans select-none">•</span> 
                                  <span className={`px-2 py-0.5 rounded text-[8px] font-bold font-mono tracking-wider ${
                                    vuln.severity === 'Critical' ? 'bg-red-500/10 text-red-400 border border-red-500/10' :
                                    vuln.severity === 'High' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/10' :
                                    vuln.severity === 'Medium' ? 'bg-yellow-500/10 text-yellow-350 border border-yellow-500/10' :
                                    vuln.severity === 'Low' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/10' :
                                    'bg-zinc-800 text-zinc-400'
                                  }`}>{vuln.severity}</span>
                                </span>
                              </div>
                            </div>
                            
                            <button
                              onClick={() => {
                                // 1. Reset filter to All so it's shown
                                setVulnFilter("All");
                                // 2. Expand this vulnerability
                                setExpandedVuln(vuln.id);
                                // 3. Smooth scroll with custom offset
                                setTimeout(() => {
                                  const el = document.getElementById(`vuln-detail-${vuln.id}`);
                                  if (el) {
                                    el.scrollIntoView({ behavior: "smooth", block: "center" });
                                  }
                                }, 100);
                              }}
                              className="px-3.5 py-1.5 bg-zinc-900 hover:bg-[#a3e635] text-[#a3e635] hover:text-black border border-zinc-800 hover:border-transparent text-[10px] font-extrabold uppercase tracking-widest rounded transition-all shrink-0 cursor-pointer shadow-sm active:scale-95"
                            >
                              View Report
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Decorative Section Divider with label */}
                  <div className="flex items-center gap-4 my-2 select-none">
                    <div className="h-px bg-gradient-to-r from-[#a3e635]/15 via-zinc-800 to-transparent flex-1" />
                    <span className="text-[9px] font-mono uppercase tracking-widest text-zinc-650 font-semibold shrink-0">Security Diagnostics Ledger</span>
                    <div className="h-px bg-gradient-to-l from-[#a3e635]/15 via-zinc-800 to-transparent flex-1" />
                  </div>

                  {/* Vulnerabilities Breakdown Findings */}
                  <div id="velora-vulnerabilities-findings" className="bg-[#0b0b0c]/90 rounded-2xl border border-zinc-850 p-6 flex flex-col gap-5 shadow-2xl backdrop-blur-md">
                    <div className="flex items-center justify-between border-b border-zinc-900 pb-4">
                      <div className="flex items-center gap-2.5">
                        <ShieldAlert className="w-5 h-5 text-[#a3e635]" />
                        <h3 className="text-sm font-bold text-white tracking-wider uppercase font-display">
                          Audit findings database ({filteredVulns.length})
                        </h3>
                      </div>
                      {vulnFilter !== "All" && (
                        <button
                          onClick={() => setVulnFilter("All")}
                          className="text-[10px] text-emerald-400 hover:text-white bg-emerald-950/40 px-3 py-1.5 rounded-xl border border-emerald-500/20 font-mono transition font-bold"
                        >
                          Clear Filter: {vulnFilter}
                        </button>
                      )}
                    </div>

                    {filteredVulns.length === 0 ? (
                      <div className="text-center py-10 flex flex-col items-center justify-center bg-zinc-950/20 rounded-xl border border-dashed border-zinc-900">
                        <CheckCircle2 className="w-10 h-10 text-emerald-500 mb-3" />
                        <p className="text-xs font-bold text-white tracking-wide">Category Threat Cleaned.</p>
                        <p className="text-[11px] text-zinc-500 mt-1 max-w-xs px-4 font-sans">
                          Our automated static analyzers bypassed or cleared these security directive vectors on current scope.
                        </p>
                      </div>
                    ) : (
                      <div className="flex flex-col gap-4">
                        {filteredVulns.map((vuln) => {
                          const isExpanded = expandedVuln === vuln.id;
                          return (
                            <div
                              key={vuln.id}
                              id={`vuln-detail-${vuln.id}`}
                              className={`rounded-2xl overflow-hidden transition-all duration-300 border ${
                                isExpanded 
                                  ? `${getSeverityBorderColorClass(vuln.severity)} shadow-xl shadow-black/90` 
                                  : "border-zinc-900 hover:border-zinc-800 bg-zinc-950/50"
                              }`}
                            >
                              {/* Header Bar */}
                              <div
                                onClick={() => setExpandedVuln(isExpanded ? null : vuln.id)}
                                className={`p-4 flex items-center justify-between gap-3 cursor-pointer select-none transition ${
                                  isExpanded ? "bg-zinc-900/10" : "hover:bg-zinc-900/30"
                                }`}
                              >
                                <div className="flex flex-wrap items-center gap-2.5">
                                  <span className="font-mono text-xs text-[#a3e635] bg-black px-2.5 py-0.5 rounded border border-zinc-900 font-bold">
                                    {vuln.id}
                                  </span>
                                  <span className={`px-2.5 py-0.5 rounded text-[9px] uppercase font-mono tracking-wider font-bold ${getSeverityBadgeClass(vuln.severity)}`}>
                                    {vuln.severity}
                                  </span>
                                  <span className="font-bold text-white text-xs sm:text-sm tracking-wide font-display">
                                    {vuln.title}
                                  </span>
                                </div>
                                <div className="flex items-center gap-2.5 shrink-0">
                                  <span className="text-[10px] text-zinc-500 font-mono hidden sm:inline bg-zinc-900 px-2 py-0.5 rounded border border-zinc-850">
                                    Line {vuln.lineNumber}
                                  </span>
                                  {isExpanded ? (
                                    <ChevronUp className="w-4 h-4 text-zinc-400" />
                                  ) : (
                                    <ChevronDown className="w-4 h-4 text-zinc-400" />
                                  )}
                                </div>
                              </div>

                              {/* Expanded Panel */}
                              {isExpanded && (
                                <div className="border-t border-zinc-900 p-5 flex flex-col gap-5 bg-zinc-950/45 backdrop-blur-sm animate-fade-in">
                                  
                                  {/* Description & Impact */}
                                  <div className="flex flex-col gap-2 bg-black/40 p-4 rounded-xl border border-zinc-900">
                                    <span className="text-[10px] uppercase tracking-widest text-[#a3e635] font-bold font-mono flex items-center gap-2">
                                      <Info className="w-3.5 h-3.5" />
                                      Detailed Vector Description
                                    </span>
                                    <p className="text-xs text-zinc-300 leading-relaxed font-sans font-normal ml-5">
                                      {vuln.description}
                                    </p>
                                  </div>

                                  {/* PoC Exploitation Flow */}
                                  <div className="flex flex-col gap-2 bg-black/40 p-4 rounded-xl border border-zinc-900">
                                    <span className="text-[10px] uppercase tracking-widest text-orange-400 font-bold font-mono flex items-center gap-2">
                                      <Zap className="w-3.5 h-3.5 text-orange-400 fill-orange-400/20" />
                                      Attack Trajectory (Concept Proof)
                                    </span>
                                    <div className="bg-zinc-950 p-4 rounded-xl border border-zinc-900 ml-5 font-mono text-xs text-zinc-300 leading-relaxed bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-zinc-900/50 via-zinc-950 to-zinc-950">
                                      {vuln.proofOfConcept}
                                    </div>
                                  </div>

                                  {/* Side By Side Code Block Comparison */}
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                                    {/* Vulnerable block */}
                                    <div className="flex flex-col gap-1.5">
                                      <div className="text-[10px] text-red-400 font-mono px-3.5 py-2 bg-red-950/15 border-x border-t border-red-500/10 rounded-t-xl flex items-center justify-between font-bold">
                                        <div className="flex items-center gap-2">
                                          <XCircle className="w-3.5 h-3.5 text-red-500" />
                                          VULNERABLE DEPLOYMENT (LINE {vuln.lineNumber})
                                        </div>
                                        {/* Mock IDE dots */}
                                        <div className="flex gap-1.5">
                                          <span className="w-2.5 h-2.5 rounded-full bg-red-500/40" />
                                          <span className="w-2.5 h-2.5 rounded-full bg-zinc-800" />
                                          <span className="w-2.5 h-2.5 rounded-full bg-zinc-800" />
                                        </div>
                                      </div>
                                      <pre className="text-[11px] text-zinc-400 font-mono p-4.5 bg-black rounded-b-xl border border-zinc-900 overflow-x-auto min-h-24 leading-relaxed max-w-full">
                                        {vuln.codeSnippet}
                                      </pre>
                                    </div>

                                    {/* Secured block */}
                                    <div className="flex flex-col gap-1.5">
                                      <div className="text-[10px] text-emerald-300 font-mono px-3.5 py-2 bg-emerald-950/20 border-x border-t border-emerald-500/10 rounded-t-xl flex items-center justify-between font-bold">
                                        <div className="flex items-center gap-2">
                                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                                          REMEDIATED CORRECT DEPLOYMENT
                                        </div>
                                        {/* Mock IDE dots */}
                                        <div className="flex gap-1.5">
                                          <span className="w-2.5 h-2.5 rounded-full bg-zinc-800" />
                                          <span className="w-2.5 h-2.5 rounded-full bg-zinc-800" />
                                          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/40" />
                                        </div>
                                      </div>
                                      <pre className="text-[11px] text-emerald-300 font-mono p-4.5 bg-zinc-950 border border-zinc-900 rounded-b-xl overflow-x-auto min-h-24 leading-relaxed max-w-full">
                                        {vuln.remediation}
                                      </pre>
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {/* Gas Optimizations Card */}
                  {auditReport.gasOptimizations && auditReport.gasOptimizations.length > 0 && (
                    <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-5 flex flex-col gap-4">
                      <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                        <div className="flex items-center gap-2">
                          <Cpu className="w-4 h-4 text-emerald-400" />
                          <h3 className="text-sm font-semibold text-white">Gas Optimization Reports ({auditReport.gasOptimizations.length})</h3>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {auditReport.gasOptimizations.map((gas, idx) => (
                          <div key={idx} className="bg-zinc-950 border border-zinc-850 p-4 rounded-xl flex flex-col gap-2">
                            <div className="flex items-center gap-2">
                              <span className="p-1 bg-emerald-950/50 rounded border border-emerald-500/10 text-emerald-400">
                                <Zap className="w-3 h-3 fill-emerald-400" />
                              </span>
                              <span className="text-xs font-semibold text-white">{gas.title}</span>
                            </div>
                            <p className="text-[11px] text-zinc-400 leading-relaxed mb-1">
                              {gas.description}
                            </p>
                            <div className="mt-auto">
                              <span className="text-[10px] text-zinc-500 font-mono uppercase tracking-wider block mb-1">Optimined Assembly Outline</span>
                              <pre className="text-[10px] font-mono p-2 bg-zinc-900 text-zinc-300 rounded overflow-x-auto border border-zinc-850">
                                {gas.remediation}
                              </pre>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                </div>
              )}

            </div>
          </div>
        )}

        {/* 2. WEBSITES DAPP FRONTEND SECURE SCANS */}
        {activeTab === "websites" && (
          <div className="flex flex-col gap-6">
            
            {/* Input Card */}
            <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-5 flex flex-col gap-4">
              <div className="flex flex-col gap-1">
                <h3 className="text-sm font-semibold text-white">dApp Frontend Sandbox Scanning Guard</h3>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  Web3 applications are key vectors for domain hijacking, SSL stripping, frame injection patterns, and missing HTTP headers. Scan your dApp’s frontend infrastructure in seconds.
                </p>
              </div>

              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-zinc-500 text-xs font-mono select-none">
                    HTTPS://
                  </span>
                  <input
                    type="text"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="uniswap.org"
                    className="w-full bg-zinc-950 text-xs pl-20 pr-4 py-3 rounded-xl border border-zinc-800 focus:outline-none focus:ring-1 focus:ring-emerald-500/40 text-white font-mono placeholder:text-zinc-600"
                    onKeyDown={(e) => e.key === "Enter" && handleRunUrlScan()}
                  />
                </div>
                <button
                  onClick={handleRunUrlScan}
                  disabled={isScanningUrl}
                  className="px-6 py-3 bg-gradient-to-r from-emerald-500 to-lime-400 hover:from-emerald-400 hover:to-lime-300 disabled:from-zinc-800 disabled:to-zinc-850 disabled:bg-zinc-800 text-black font-bold rounded-xl text-xs leading-none uppercase tracking-wider transition-all duration-300 cursor-pointer disabled:text-zinc-600 disabled:cursor-not-allowed shrink-0 flex items-center justify-center gap-2"
                >
                  {isScanningUrl ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin shrink-0" />
                      PING HANDSHAKE...
                    </>
                  ) : (
                    <>
                      <Search className="w-3.5 h-3.5 shrink-0" />
                      Scan Frontend Host
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Scanning Progress Loader */}
            {isScanningUrl && (
              <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-8 text-center flex flex-col items-center justify-center gap-3 py-14 animate-fade-in">
                <div className="w-14 h-14 relative flex items-center justify-center">
                  <div className="absolute inset-x-0 inset-y-0 rounded-full border border-emerald-500/10 border-t-emerald-500 animate-spin" />
                  <Globe className="w-5 h-5 text-emerald-400" />
                </div>
                <div className="text-xs font-bold text-white uppercase tracking-wider">Establishing Connection Handshake</div>
                <p className="text-[11px] text-zinc-500 max-w-sm leading-relaxed">
                  Velora Proxy Auditor is fetching secure endpoint HTTP parameters, security payload headers, CDN script bundles, and testing against known domain Hijack vectors.
                </p>
              </div>
            )}

            {/* SCANNING RESULTS CARDS */}
            {scanReport && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 animate-fade-in col-span-12">
                
                {/* Premium Website Scan Action Banner with Download Button */}
                <div id="website-scan-action-banner" className="lg:col-span-12 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-gradient-to-r from-emerald-950/25 to-zinc-950 border border-zinc-800 rounded-2xl p-5 shadow-xl backdrop-blur-sm">
                  <div>
                    <span className="text-[10px] font-mono tracking-widest uppercase text-[#a3e635] font-semibold block mb-0.5">dApp Frontend Scan Completed</span>
                    <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                      Web3 Frontend Security Report for {scanReport.url}
                    </h3>
                    <p className="text-[11px] text-zinc-400">Security headers assessment, SSL validation, script diagnostics, and linked ecosystem smart contracts</p>
                  </div>
                  
                  <button
                    id="download-website-scan-btn"
                    onClick={handleDownloadWebsiteScanReport}
                    className="inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-[#a3e635] to-emerald-400 hover:from-lime-400 hover:to-emerald-300 text-black font-bold text-xs uppercase tracking-widest rounded-xl transition-all duration-300 shadow-md shadow-emerald-500/10 hover:shadow-emerald-400/20 active:scale-98 cursor-pointer border border-[#a3e635]/20 shrink-0"
                  >
                    <Download className="w-4 h-4" />
                    Download Frontend Report (.MD)
                  </button>
                </div>

                {/* Score Card Panel */}
                <div className="lg:col-span-4 flex flex-col gap-6">
                  
                  {/* Performance Summary Grade */}
                  <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-5 flex flex-col gap-4 text-center">
                    <span className="text-[10px] text-zinc-500 font-mono uppercase tracking-widest block">FRONTEND SECURITY RATING</span>
                    
                    <div className="flex flex-col items-center justify-center my-1 select-none">
                      <div className={`text-6xl font-black py-4 px-6 rounded-3xl border ${getScoreBg(scanReport.securityScore || 0)} ${getScoreColor(scanReport.securityScore || 0)}`}>
                        {scanReport.securityScore && scanReport.securityScore >= 85 ? "A" : scanReport.securityScore && scanReport.securityScore >= 60 ? "C" : "F"}
                      </div>
                      <span className="text-2xl font-bold text-white mt-4">{scanReport.securityScore}/100</span>
                    </div>

                    <div className="h-px bg-zinc-800/60 my-1" />

                    <div className="flex flex-col gap-2 text-left">
                      <div className="flex justify-between items-center text-xs text-zinc-400">
                        <span>Audited Domain:</span>
                        <span className="font-mono text-white text-right truncate max-w-36">{scanReport.url}</span>
                      </div>
                      <div className="flex justify-between items-center text-xs text-zinc-400">
                        <span>SSL Verification:</span>
                        <span className={`flex items-center gap-1 font-mono ${scanReport.isHttps ? "text-emerald-400" : "text-red-400"}`}>
                          {scanReport.isHttps ? (
                            <>
                              <Lock className="w-3 h-3" /> Enabled (HTTPS)
                            </>
                          ) : (
                            <>
                              <Unlock className="w-3 h-3" /> Insecure (HTTP)
                            </>
                          )}
                        </span>
                      </div>
                      <div className="flex justify-between items-center text-xs text-zinc-400">
                        <span>Response Time:</span>
                        <span className="font-mono text-white">{scanReport.responseTimeMs} ms</span>
                      </div>
                      <div className="flex justify-between items-center text-xs text-zinc-400">
                        <span>Overall Threat Verdict:</span>
                        <span className={`font-semibold ${
                          scanReport.verdict === "Low Risk" ? "text-emerald-400" : scanReport.verdict === "Medium Risk" ? "text-yellow-400" : "text-red-400"
                        }`}>{scanReport.verdict}</span>
                      </div>
                    </div>
                  </div>

                  {/* Header parameters */}
                  <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-5 flex flex-col gap-3">
                    <span className="text-[10px] text-zinc-500 font-mono uppercase tracking-widest border-b border-zinc-800 pb-2">HOST INFRASTRUCTURE parameters</span>
                    
                    <div className="flex flex-col gap-3 mt-1 text-xs">
                      <div className="flex flex-col gap-0.5">
                        <span className="text-zinc-500 font-mono text-[10px]">SERVER SIGNATURE</span>
                        <span className="font-mono text-white truncate">{scanReport.headers?.server}</span>
                      </div>
                      <div className="flex flex-col gap-0.5">
                        <span className="text-zinc-500 font-mono text-[10px]">X-POWERED-BY FRAMEWORK</span>
                        <span className="font-mono text-white truncate">{scanReport.headers?.xPoweredBy}</span>
                      </div>
                      <div className="flex flex-col gap-0.5">
                        <span className="text-zinc-500 font-mono text-[10px]">CONTENT-TYPE MIME</span>
                        <span className="font-mono text-white truncate">{scanReport.headers?.contentType}</span>
                      </div>
                      <div className="flex flex-col gap-0.5">
                        <span className="text-zinc-500 font-mono text-[10px]">CACHE CONTROL INSTRUCTION</span>
                        <span className="font-mono text-white truncate text-[11px] max-w-full block overflow-hidden">{scanReport.headers?.cacheControl}</span>
                      </div>
                    </div>
                  </div>

                </div>

                {/* Audit Checklist Panels */}
                <div className="lg:col-span-8 flex flex-col gap-6">
                  
                  {/* Header checklist */}
                  <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-5 flex flex-col gap-4">
                    <div className="flex items-center gap-2 border-b border-zinc-800 pb-3">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      <h3 className="text-sm font-semibold text-white">HTTP Security Headers Diagnostic Card</h3>
                    </div>

                    <div className="flex flex-col gap-3.5">
                      {scanReport.headerAssessments?.map((assessment, idx) => (
                        <div
                          key={idx}
                          className={`p-4 rounded-xl border transition-all duration-200 flex flex-col sm:flex-row sm:items-start justify-between gap-4 relative overflow-hidden pl-5 ${
                            assessment.present
                              ? "bg-gradient-to-r from-emerald-950/10 to-zinc-950/5 border-emerald-500/15 hover:border-emerald-500/25 shadow-sm"
                              : "bg-gradient-to-r from-red-950/10 to-zinc-950/5 border-red-500/15 hover:border-red-500/25 shadow-sm"
                          }`}
                        >
                          {/* Colorful Left Indicator Accent Bar */}
                          <div className={`absolute top-0 left-0 bottom-0 w-1 ${
                            assessment.present ? "bg-emerald-500" : "bg-red-500"
                          }`} />

                          <div className="flex-1 flex flex-col gap-0.5">
                            <span className="text-xs font-semibold text-white flex items-center gap-2 flex-wrap">
                              {assessment.present ? (
                                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                              ) : (
                                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                              )}
                              <span className={assessment.present ? "text-emerald-100" : "text-red-100"}>
                                {assessment.name}
                              </span>
                              <span className="text-[10px] font-mono text-zinc-500 font-normal">
                                ({assessment.header})
                              </span>
                            </span>
                            <p className="text-[11px] text-zinc-400 leading-relaxed mt-1.5 pl-6">
                              {assessment.recommendation}
                            </p>
                            {assessment.present && (
                              <div className="mt-2 text-[10px] font-mono text-emerald-400 bg-emerald-950/20 p-2 rounded-lg max-w-full overflow-hidden truncate pl-3 border border-emerald-500/10 ml-6">
                                <span className="text-zinc-500 mr-1.5">Returned Value:</span>
                                {assessment.value}
                              </div>
                            )}
                          </div>

                          <div className="sm:text-right shrink-0 flex sm:flex-col items-center sm:items-end justify-between sm:justify-start gap-2 ml-6 sm:ml-0">
                            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider flex items-center gap-1 ${
                              assessment.present
                                ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                                : "bg-red-500/10 text-red-400 border border-red-500/20"
                            }`}>
                              {assessment.present ? "PASSED" : "MISSING"}
                            </span>
                            {!assessment.present && (
                              <span className="text-[10px] text-zinc-400 font-mono">
                                Severity: <span className="text-red-400 font-semibold">{assessment.severity}</span>
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Web3 Javascript indicators */}
                  <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-5 flex flex-col gap-4">
                    <div className="flex items-center gap-2 border-b border-zinc-800 pb-3">
                      <Code2 className="w-4 h-4 text-emerald-400" />
                      <h3 className="text-sm font-semibold text-white">Injected Web3 Script Audit Dossier</h3>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      {[
                        { label: "Wagmi Library Usage", value: scanReport.web3Indicators?.usesWagmi },
                        { label: "Ethers.js Client", value: scanReport.web3Indicators?.usesEthers },
                        { label: "MetaMask Providers", value: scanReport.web3Indicators?.usesMetamaskIndicator },
                        { label: "WalletConnect API", value: scanReport.web3Indicators?.usesWalletConnect }
                      ].map((ind, idx) => (
                        <div key={idx} className="bg-zinc-950 border border-zinc-850 p-3 rounded-xl flex items-center justify-between text-xs">
                          <span className="text-zinc-400 font-medium text-[11px] leading-tight pr-1">{ind.label}</span>
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono uppercase shrink-0 ${
                            ind.value
                              ? "bg-emerald-950/40 text-emerald-400 border border-emerald-500/10"
                              : "bg-zinc-900 text-zinc-600 border border-zinc-850"
                          }`}>
                            {ind.value ? "YES" : "NO"}
                          </span>
                        </div>
                      ))}
                    </div>

                    {/* Insecure CDN scripts */}
                    {scanReport.web3Indicators?.insecureExternalScripts &&
                    scanReport.web3Indicators.insecureExternalScripts.length > 0 ? (
                      <div className="mt-2 bg-red-950/20 border border-red-500/20 rounded-xl p-4 flex flex-col gap-2">
                        <span className="text-xs font-semibold text-red-400 flex items-center gap-1.5">
                          <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
                          Unsecured External Script Bundles Detected!
                        </span>
                        <p className="text-[11px] text-zinc-400 leading-relaxed">
                          The dApp frontend includes external scripts over unsecured plain HTTP boundaries. This permits adversary routers to perform Man-in-the-Middle hijacking and swap wallet injection addresses.
                        </p>
                        <div className="flex flex-col gap-1.5 mt-1 font-mono text-[10px] text-zinc-300">
                          {scanReport.web3Indicators.insecureExternalScripts.map((script, idx) => (
                            <span key={idx} className="bg-zinc-950 p-2 rounded border border-zinc-900 overflow-hidden truncate block">
                              {script}
                            </span>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="mt-1 flex items-center gap-2 text-xs text-zinc-400 leading-tight bg-zinc-950/50 p-3.5 rounded-xl border border-zinc-850">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        <span>No unsecured, plain HTTP external script URLs detected in initial index sweeps. Safe loading context.</span>
                      </div>
                    )}
                  </div>

                  {/* Connected Smart Contracts Audit Panel */}
                  {scanReport.connectedContracts && scanReport.connectedContracts.length > 0 && (
                    <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-5 flex flex-col gap-4">
                      <div className="flex flex-col gap-1 border-b border-zinc-800 pb-3">
                        <div className="flex items-center gap-2">
                          <Cpu className="w-4 h-4 text-emerald-400" />
                          <h3 className="text-sm font-semibold text-white">Connected Ecosystem Smart Contracts ({scanReport.connectedContracts.length})</h3>
                        </div>
                        <p className="text-[11px] text-zinc-400 leading-relaxed mt-0.5">
                          EVM smart contracts linked to or invoked within this website's scraped ecosystem. Click a contract to open its deep sandbox security audit report.
                        </p>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                        {scanReport.connectedContracts.map((contract, cIdx) => {
                          const isContractSelected = selectedScanContract === cIdx;
                          const score = contract.auditReport?.securityScore || 100;
                          return (
                            <div
                              key={cIdx}
                              onClick={() => {
                                if (isContractSelected) {
                                  setSelectedScanContract(null);
                                  setShowConnectedReportDetails(false);
                                } else {
                                  setSelectedScanContract(cIdx);
                                  setShowConnectedReportDetails(false);
                                }
                              }}
                              className={`p-4 rounded-xl border cursor-pointer flex justify-between items-start gap-4 transition-all duration-200 select-none ${
                                isContractSelected
                                  ? "bg-zinc-950 border-emerald-500/50 ring-1 ring-emerald-500/20"
                                  : "bg-zinc-950/60 border-zinc-850 hover:border-zinc-800 hover:bg-zinc-900/10"
                              }`}
                            >
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                                  <span className="text-xs font-semibold text-white truncate">{contract.name}</span>
                                  <span className="text-[9px] font-mono bg-zinc-900 px-1.5 py-0.5 rounded text-zinc-500 border border-zinc-850 uppercase">
                                    {contract.type}
                                  </span>
                                </div>
                                <div className="text-[10px] text-zinc-400 font-mono truncate max-w-full">
                                  {contract.address}
                                </div>
                                <div className="text-[10px] text-zinc-500 font-mono mt-1">
                                  Network: {contract.network}
                                </div>
                              </div>

                              <div className="text-right shrink-0 flex flex-col items-end gap-1.5">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-tight ${getScoreBg(score)}`}>
                                  Score: {score}
                                </span>
                                <span className="text-[10px] text-zinc-400 font-medium flex items-center gap-1">
                                  {isContractSelected ? "Collapse ▲" : "Audit details ▼"}
                                </span>
                              </div>
                            </div>
                          );
                        })}
                      </div>

                      {/* Inspected Connected Contract Audit Details */}
                      {selectedScanContract !== null && scanReport.connectedContracts[selectedScanContract] && (
                        (() => {
                          const contract = scanReport.connectedContracts[selectedScanContract];
                          const report = contract.auditReport;
                          return (
                            <div className="mt-4 p-4 rounded-xl border border-zinc-800 bg-zinc-950/40 flex flex-col gap-5 animate-fade-in">
                              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800/80 pb-3">
                                <div>
                                  <div className="flex items-center gap-2">
                                    <span className="text-xs font-bold text-emerald-400 font-mono uppercase tracking-widest bg-emerald-950/25 border border-emerald-500/10 px-2 py-0.5 rounded">
                                      SANDBOX SEC-AUDIT REPORT
                                    </span>
                                    <span className="text-[11px] font-mono text-zinc-500">
                                      {contract.name}
                                    </span>
                                  </div>
                                  <span className="text-[10px] text-zinc-500 font-mono block mt-1">
                                    Target EVM Hash: {contract.address}
                                  </span>
                                </div>

                                <div className="flex items-center gap-2">
                                  <span className="text-[11px] text-zinc-500 font-mono">Security integrity:</span>
                                  <span className={`px-2 py-1 rounded-lg text-xs font-mono font-black ${getScoreBg(report?.securityScore || 100)}`}>
                                    {report?.securityScore || 100}/100
                                  </span>
                                </div>
                              </div>

                              {/* Heuristics summary */}
                              {report?.summary && (
                                <div className="flex flex-col gap-1.5 bg-zinc-900/35 p-3.5 rounded-xl border border-zinc-850">
                                  <span className="text-[10px] tracking-wider text-zinc-500 uppercase font-mono flex items-center gap-1.5 font-bold">
                                    <Info className="w-3.5 h-3.5 text-zinc-500" />
                                    Audit Ecosystem Summary & Diagnosis
                                  </span>
                                  <p className="text-xs text-zinc-300 leading-relaxed">
                                    {report.summary}
                                  </p>
                                </div>
                              )}

                              {/* Action Controls Panel */}
                              <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-black border border-zinc-850/80 rounded-xl p-4.5">
                                <div className="flex flex-col text-left">
                                  <span className="text-[10px] uppercase font-mono tracking-widest text-[#a3e635] font-bold">Audit findings controls</span>
                                  <span className="text-xs font-semibold text-white mt-0.5">Vulnerability & Gas Performance Details</span>
                                </div>

                                <div className="flex flex-wrap items-center gap-2">
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handleDownloadConnectedContractReport(selectedScanContract);
                                    }}
                                    className="inline-flex items-center gap-1.5 px-3 py-2 bg-zinc-900 hover:bg-zinc-850 text-emerald-400 border border-emerald-500/20 hover:border-emerald-500/40 text-[10px] font-bold uppercase tracking-wide rounded-lg transition-all duration-250 cursor-pointer"
                                  >
                                    <Download className="w-3.5 h-3.5 shrink-0" />
                                    Download Contract Report (.MD)
                                  </button>

                                  <button
                                    onClick={() => setShowConnectedReportDetails(!showConnectedReportDetails)}
                                    className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-[10px] font-bold uppercase tracking-wide transition-all duration-250 cursor-pointer border ${
                                      showConnectedReportDetails
                                        ? "bg-amber-400/10 text-amber-400 border-amber-400/20 hover:bg-amber-400/20"
                                        : "bg-[#a3e635] text-black border-transparent hover:bg-lime-400"
                                    }`}
                                  >
                                    {showConnectedReportDetails ? (
                                      <>
                                        <span>Hide Full Findings ▲</span>
                                      </>
                                    ) : (
                                      <>
                                        <span>Show Full Findings ({report?.vulnerabilities?.length || 0}) ▼</span>
                                      </>
                                    )}
                                  </button>
                                </div>
                              </div>

                              {showConnectedReportDetails && (
                                <div className="flex flex-col gap-5 border-t border-zinc-900 pt-4 animate-fade-in">
                                  {/* Vulnerability items */}
                                  {report?.vulnerabilities && report.vulnerabilities.length > 0 && (
                                    <div className="flex flex-col gap-3">
                                      <span className="text-[10px] tracking-wider text-red-400 uppercase font-mono flex items-center gap-1.5 font-bold">
                                        <ShieldAlert className="w-4 h-4 text-red-500" />
                                        Identified Ecosystem Threat Vectors ({report.vulnerabilities.length})
                                      </span>

                                      <div className="flex flex-col gap-3">
                                        {report.vulnerabilities.map((vuln, vIdx) => (
                                          <div key={vIdx} className="bg-zinc-900/60 border border-zinc-800 p-4 rounded-xl flex flex-col gap-3">
                                            <div className="flex items-center justify-between gap-3 flex-wrap">
                                              <div className="flex items-center gap-2 flex-wrap">
                                                <span className="font-mono text-[10px] text-zinc-400 bg-zinc-950 px-2 py-0.5 rounded border border-zinc-850">
                                                  {vuln.id}
                                                </span>
                                                <span className={`px-1.5 py-0.5 rounded text-[9px] uppercase font-mono tracking-wider ${getSeverityBadgeClass(vuln.severity)}`}>
                                                  {vuln.severity}
                                                </span>
                                                <span className="text-xs font-semibold text-white">
                                                  {vuln.title}
                                                </span>
                                              </div>
                                              <span className="text-[10px] text-zinc-500 font-mono">
                                                Approx Line {vuln.lineNumber}
                                              </span>
                                            </div>

                                            <p className="text-[11px] text-zinc-400 leading-relaxed px-0.5">
                                              {vuln.description}
                                            </p>

                                            {vuln.proofOfConcept && (
                                              <div className="flex flex-col gap-1.5 bg-zinc-950/70 p-3 rounded-lg border border-zinc-900">
                                                <span className="text-[9px] font-mono uppercase text-orange-400 tracking-wider font-semibold">
                                                  Exploit Trajectory Scenario:
                                                </span>
                                                <p className="text-[10px] text-zinc-400 font-mono leading-relaxed whitespace-pre-line">
                                                  {vuln.proofOfConcept}
                                                </p>
                                              </div>
                                            )}

                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-1">
                                              {/* Vulnerable block */}
                                              <div className="flex flex-col gap-1">
                                                <span className="text-[9px] text-red-400 font-mono px-2 py-1 bg-red-950/15 border border-red-500/10 rounded-t flex items-center gap-1">
                                                  <XCircle className="w-3 h-3 text-red-500" />
                                                  VULNERABLE CODE BLOCK
                                                </span>
                                                <pre className="text-[10px] text-zinc-400 font-mono p-2.5 bg-zinc-950 rounded-b border-x border-b border-zinc-900 overflow-x-auto min-h-16 leading-relaxed">
                                                  {vuln.codeSnippet}
                                                </pre>
                                              </div>

                                              {/* Remediation */}
                                              <div className="flex flex-col gap-1">
                                                <span className="text-[9px] text-emerald-400 font-mono px-2 py-1 bg-emerald-950/20 border border-emerald-500/10 rounded-t flex items-center gap-1">
                                                  <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                                                  REMEDIATED SECURED BLOCK
                                                </span>
                                                <pre className="text-[10px] text-zinc-300 font-mono p-2.5 bg-zinc-950 border-x border-b border-zinc-900 rounded-b overflow-x-auto min-h-16 leading-relaxed text-emerald-250">
                                                  {vuln.remediation}
                                                </pre>
                                              </div>
                                            </div>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  {/* Gas items */}
                                  {report?.gasOptimizations && report.gasOptimizations.length > 0 && (
                                    <div className="border-t border-zinc-800/60 pt-4 flex flex-col gap-2.5">
                                      <span className="text-[10px] tracking-wider text-emerald-400 uppercase font-mono flex items-center gap-1.5 font-bold">
                                        <Zap className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                        Detected Gas Optimizations ({report.gasOptimizations.length})
                                      </span>

                                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                        {report.gasOptimizations.map((gas, gasIdx) => (
                                          <div key={gasIdx} className="bg-zinc-900/40 border border-zinc-850 p-3 rounded-lg flex flex-col justify-between gap-1.5">
                                            <div>
                                              <span className="text-[11px] font-semibold text-white block mb-0.5">{gas.title}</span>
                                              <p className="text-[10px] text-zinc-400 leading-relaxed">
                                                {gas.description}
                                              </p>
                                            </div>
                                            <pre className="text-[9px] font-mono p-2 bg-zinc-950 text-zinc-300 rounded overflow-x-auto border border-zinc-900 mt-2">
                                              {gas.remediation}
                                            </pre>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          );
                        })()
                      )}
                    </div>
                  )}

                </div>
              </div>
            )}

          </div>
        )}

        {/* 3. EXPERT SECOPS CHATBOT PANEL */}
        {activeTab === "chat" && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
            
            {/* Quick shortcuts / prompts sidebar */}
            <div className="lg:col-span-4 flex flex-col gap-6">
              <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-5 flex flex-col gap-4">
                <div className="flex items-center gap-2 border-b border-zinc-800 pb-2.5">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-white">SecOps Chat Shortcuts</h3>
                </div>
                <p className="text-xs text-zinc-400 leading-relaxed mb-1">
                  Ask specific Web3 security guidelines or click standard templates below to query Velora instantly.
                </p>

                <div className="flex flex-col gap-2.5">
                  {[
                    "How do I prevent reentrancy attacks in 2026 guidelines?",
                    "What are the security concerns with Uniswap spot oracle pricing?",
                    "Explain the risks associated with tx.origin authentication.",
                    "Draft a secure template for ERC20 token implementation."
                  ].map((presetPrompt, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleSendMessage(presetPrompt)}
                      className="text-left p-2.5 rounded-lg text-xs leading-relaxed transition bg-zinc-950 hover:bg-zinc-800/40 border border-zinc-900 hover:border-zinc-800 text-zinc-400 hover:text-white font-medium flex items-center justify-between gap-2"
                    >
                      <span className="truncate max-w-full">{presetPrompt}</span>
                      <ArrowRight className="w-3.5 h-3.5 shrink-0 text-emerald-400" />
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Chat Box Panel */}
            <div className="lg:col-span-8 flex flex-col bg-zinc-900 rounded-xl border border-zinc-800 h-[600px] overflow-hidden">
              <div className="border-b border-zinc-800 p-4 bg-zinc-900 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                  <div>
                    <h3 className="text-xs font-semibold text-white">Velora SecOps Command Bridge</h3>
                    <p className="text-[10px] text-zinc-500 font-mono">STATION: ONLINE | GEMINI-3.5-FLASH</p>
                  </div>
                </div>
              </div>

              {/* Chat Feed */}
              <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4 bg-zinc-950/20">
                {messages.map((m, idx) => (
                  <div
                    key={idx}
                    className={`flex ${m.role === "user" ? "justify-end" : "justify-start"} animate-fade-in`}
                  >
                    <div
                      className={`max-w-[85%] rounded-2xl p-3.5 text-xs leading-relaxed ${
                        m.role === "user"
                          ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 rounded-tr-none px-4"
                          : "bg-zinc-900 text-zinc-300 border border-zinc-800 rounded-tl-none pr-4"
                      }`}
                    >
                      {/* Very simple markdown code block formatter helper */}
                      <div className="whitespace-pre-wrap break-words font-sans">
                        {m.content.split("```").map((chunk, cIdx) => {
                          const isCode = cIdx % 2 === 1;
                          if (isCode) {
                            const trimmed = chunk.trim();
                            const matches = trimmed.match(/^([a-zA-Z0-9+#]+)\n/);
                            const lang = matches ? matches[1] : "";
                            const actualCode = lang ? trimmed.slice(lang.length).trim() : trimmed;
                            return (
                              <pre
                                key={cIdx}
                                className="my-2.5 p-3 rounded-lg bg-zinc-950 font-mono text-[11px] leading-relaxed border border-zinc-850 text-emerald-250 overflow-x-auto max-w-full"
                              >
                                {lang && (
                                  <span className="text-[9px] text-zinc-500 block border-b border-zinc-900 pb-1 mb-1 text-right uppercase tracking-wider font-sans">
                                    {lang}
                                  </span>
                                )}
                                {actualCode}
                              </pre>
                            );
                          }
                          return (
                            <span key={cIdx} className="leading-relaxed">
                              {chunk}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                ))}
                {isChatLoading && (
                  <div className="flex justify-start animate-pulse">
                    <div className="bg-zinc-900 rounded-xl rounded-tl-none border border-zinc-800 p-3 flex items-center gap-2">
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-emerald-500" />
                      <span className="text-xs text-zinc-500 font-mono">Generating defensive analysis...</span>
                    </div>
                  </div>
                )}
                <div ref={chatBottomRef} />
              </div>

              {/* Chat Input form */}
              <div className="border-t border-zinc-800/80 p-4 bg-zinc-900/40">
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    placeholder="Ask Velora about reentrancy, access audits, signature verification..."
                    className="flex-1 bg-zinc-950 text-xs px-4 py-3 rounded-xl border border-zinc-800 focus:outline-none focus:ring-1 focus:ring-emerald-500/40 text-white placeholder-zinc-500 font-mono"
                    onKeyDown={(e) => e.key === "Enter" && handleSendMessage()}
                  />
                  <button
                    onClick={() => handleSendMessage()}
                    disabled={isChatLoading || !chatInput.trim()}
                    className="p-3 bg-gradient-to-r from-emerald-500 to-lime-400 hover:from-emerald-400 hover:to-lime-300 disabled:from-zinc-850 disabled:to-zinc-900 text-black disabled:text-zinc-650 rounded-xl transition-all duration-300 cursor-pointer disabled:cursor-not-allowed shrink-0"
                  >
                    <Send className="w-4 h-4 fill-current" />
                  </button>
                </div>
              </div>

            </div>

          </div>
        )}

      </main>

      {/* FOOTER */}
      <footer className="border-t border-zinc-800 bg-zinc-900/40 py-5 px-4 text-center text-[10px] text-zinc-500 font-mono flex flex-col sm:flex-row items-center justify-between gap-4 max-w-7xl w-full mx-auto">
        <div>
          <span>Velora Cyber Security Platform</span>
        </div>
        <div className="flex gap-4">
          <span className="flex items-center gap-1">
            <Lock className="w-3 h-3 text-emerald-500" /> Sandboxed Environment
          </span>
          <span className="flex items-center gap-1">
            <Cpu className="w-3 h-3 text-emerald-500" /> Real-time EVM Traversal
          </span>
        </div>
      </footer>
    </div>
  );
}
