#!/usr/bin/env node

import { spawnSync } from 'child_process';

import { program } from 'commander';

import { bailWithError, generateReport, parseAdvisory } from './index.js';
import {
    AuditMetadata,
    RawAuditAdvisor,
    AuditAdvisoryData,
    Options,
    AuditMetadataData,
    AuditAdvisor,
} from './types.js';

program
    .option('-o, --output [output]', 'output file', 'yarn-audit.html')
    .option(
        '-t, --template [ejs file]',
        'ejs template file',
        new URL('../templates/template.ejs', import.meta.url).pathname
    )
    .option('--fatal-exit-code', 'exit with code 1 if vulnerabilities were found', false)
    .parse();

console.info('Checking audit logs...');

let summary: AuditMetadata;
const options = program.opts<Options>();
const vulnerabilities = new Map<string, AuditAdvisor>();

const { stdout } = spawnSync('yarn', ['--version']);

const yarnMajorVersion = Number.parseInt(stdout.toString());

let text = '';
process.stdin.on('readable', function (this: typeof process.stdin) {
    try {
        const chunk = this.read();

        if (chunk !== null) {
            text += chunk;

            const lines = text.split('\n');

            if (lines.length > 1) {
                text = lines.splice(-1, 1)[0];

                lines.forEach((line) => {
                    if (yarnMajorVersion >= 2) {
                        const auditAdvisoryData = JSON.parse(line) as {
                            advisories: Record<string, RawAuditAdvisor>;
                            metadata: AuditMetadata;
                        };

                        Object.values(auditAdvisoryData.advisories).forEach((rawAdvisory) => {
                            advisoryToVulnerabilities(rawAdvisory);
                        });

                        summary = auditAdvisoryData.metadata;
                    } else {
                        const auditAdvisoryData = JSON.parse(line) as AuditAdvisoryData | AuditMetadataData;

                        if (auditAdvisoryData.type === 'auditAdvisory') {
                            advisoryToVulnerabilities(auditAdvisoryData.data.advisory);
                        } else if (auditAdvisoryData.type === 'auditSummary') {
                            summary = auditAdvisoryData.data;
                        }
                    }
                });

                function advisoryToVulnerabilities(advisory: RawAuditAdvisor) {
                    const newVulnerabilities = parseAdvisory(advisory);

                    newVulnerabilities.forEach((newVulnerability) => {
                        const { key } = newVulnerability;

                        if (!vulnerabilities.has(key)) {
                            vulnerabilities.set(key, newVulnerability);
                        }
                    });
                }
            }
        }
    } catch (error) {
        bailWithError('Failed to parse YARN Audit JSON!', error as Error, options.fatalExitCode);
    }
});

process.stdin.on('end', async function () {
    try {
        await generateReport(Array.from(vulnerabilities.values()), summary, options);
    } catch (error) {
        bailWithError(
            'Failed to generate report! Please report this issue to https://github.com/davityavryan/yarn-audit-html/issues',
            error as Error,
            options.fatalExitCode
        );
    }
});
