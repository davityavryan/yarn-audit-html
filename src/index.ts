import fs from 'fs';

import ejs from 'ejs';
import { marked } from 'marked';

import { AuditAdvisor, AuditMetadata, Options, RawAuditAdvisor, Severity, Vulnerabilities } from './types.js';

const bootstrapClassSeverityMap: Record<Severity, string> = {
    critical: 'danger',
    high: 'warning',
    moderate: 'info',
    low: 'primary',
    info: 'secondary',
};
const severitySortPriority = Object.keys(bootstrapClassSeverityMap);

export function parseAdvisory(advisory: RawAuditAdvisor) {
    const vulnerabilities: Vulnerabilities = {};

    advisory.findings.forEach((finding) => {
        const { version } = finding;
        const key = `${advisory.module_name}@${version}-${advisory.vulnerable_versions}-${advisory.created}.${advisory.cwe}`;

        if (!(key in vulnerabilities)) {
            vulnerabilities[key] = {
                ...advisory,
                key,
                version,
                paths: finding.paths,
            };
        } else {
            vulnerabilities[key].paths = [...vulnerabilities[key].paths, ...finding.paths];
        }
    });

    Object.entries(vulnerabilities).forEach(([key, vulnerability]) => {
        vulnerabilities[key].paths = Array.from(new Set(vulnerability.paths));
    });

    return Object.values(vulnerabilities);
}

export async function generateReport(vulnerabilities: AuditAdvisor[], summary: AuditMetadata, options: Options) {
    vulnerabilities.sort(
        (left, right) => severitySortPriority.indexOf(left.severity) - severitySortPriority.indexOf(right.severity)
    );

    const report = await renderReport(
        {
            reportDate: new Date(),
            vulnerabilities,
            theme: options.theme,
            summary: {
                vulnerabilities: Object.values(summary.vulnerabilities).reduce((sum, value) => sum + value, 0),
                totalDependencies: summary.totalDependencies,
            },
        },
        options.template
    );

    await writeReport(options.output, report);

    if (vulnerabilities.length > 0) {
        console.info(`Found ${vulnerabilities.length} vulnerabilities. Report is saved in "${options.output}"`);

        if (options.fatalExitCode) {
            return process.exit(1);
        }
    } else {
        console.info('Congrats!!! No vulnerabilities found.');
    }

    return process.exit(0);
}

export async function renderReport(data: ejs.Data, template: string) {
    const htmlTemplate = await fs.promises.readFile(template, 'utf8');

    return ejs.render(htmlTemplate, {
        data,
        formatDate: (dateStr: string) => new Date(dateStr).toLocaleString(),
        severityClass: (severity: Severity) => bootstrapClassSeverityMap[severity],
        markdown: marked,
    });
}

export async function writeReport(outputPath: string, report: string) {
    await fs.promises.writeFile(outputPath, report, { encoding: 'utf8' });
}

export function bailWithError(message: string, error: Error, isFatalExitCode: boolean) {
    console.error(`${message}\n`, error);

    if (isFatalExitCode) {
        return process.exit(1);
    }

    return process.exit(0);
}
