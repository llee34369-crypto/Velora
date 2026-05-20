export type VulnerabilitySeverity = "Critical" | "High" | "Medium" | "Low" | "Informational";

export interface Vulnerability {
  id: string;
  title: string;
  severity: VulnerabilitySeverity;
  description: string;
  lineNumber: number;
  codeSnippet: string;
  proofOfConcept: string;
  remediation: string;
}

export interface GasOptimization {
  title: string;
  description: string;
  remediation: string;
}

export interface AuditReport {
  securityScore: number;
  vulnerabilities: Vulnerability[];
  gasOptimizations: GasOptimization[];
  summary: string;
}

export interface HeaderAssessment {
  name: string;
  header: string;
  present: boolean;
  value: string;
  recommendation: string;
  severity: "High" | "Medium" | "Low" | "Informational";
}

export interface Web3Indicators {
  usesWagmi: boolean;
  usesEthers: boolean;
  usesMetamaskIndicator: boolean;
  usesWalletConnect: boolean;
  insecureExternalScripts: string[];
}

export interface ConnectedContract {
  address: string;
  name: string;
  network: string;
  type: string;
  auditReport?: AuditReport;
}

export interface WebsiteScanReport {
  success: boolean;
  url: string;
  origin?: string;
  isHttps?: boolean;
  responseTimeMs?: number;
  securityScore?: number;
  headers?: {
    server: string;
    xPoweredBy: string;
    contentType: string;
    cacheControl: string;
  };
  headerAssessments?: HeaderAssessment[];
  web3Indicators?: Web3Indicators;
  connectedContracts?: ConnectedContract[];
  verdict?: "Low Risk" | "Medium Risk" | "High Vulnerability Risk";
  reason?: string;
}
