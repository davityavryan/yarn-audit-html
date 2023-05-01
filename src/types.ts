export type Severity = 'info' | 'low' | 'moderate' | 'high' | 'critical';

export type RawAuditAdvisor = {
    access: string;
    created: string;
    cves: string[];
    cvss: { score: number; vectorString: string };
    cwe: string[];
    deleted: boolean | null;
    findings: { version: string; paths: string[]; dev?: boolean; optional?: boolean; bundled?: boolean }[];
    found_by: { name: string } | null;
    github_advisory_id?: string;
    id: number;
    metadata: { module_type: string; exploitability: number; affected_components: string } | null;
    module_name: string;
    npm_advisory_id: null;
    overview: string;
    patched_versions: string;
    recommendation: string;
    references: string;
    reported_by: { name: string } | null;
    severity: Severity;
    title: string;
    updated: string;
    url: string;
    vulnerable_versions: string;
};

export type AuditAdvisor = RawAuditAdvisor & {
    key: string;
    version: string;
    paths: string[];
};

export type AuditVulnerabilityCounts = Record<Severity, number>;

export type AuditMetadata = {
    vulnerabilities: AuditVulnerabilityCounts;
    dependencies: number;
    devDependencies: number;
    optionalDependencies: number;
    totalDependencies: number;
};

export type Vulnerabilities = Record<string, AuditAdvisor>;

export type AuditAdvisoryData = {
    type: 'auditAdvisory';
    data: {
        advisory: RawAuditAdvisor;
    };
};

export type AuditMetadataData = {
    type: 'auditSummary';
    data: AuditMetadata;
};

export type Options = {
    output: string;
    template: string;
    fatalExitCode: boolean;
};
