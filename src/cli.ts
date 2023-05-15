#!/usr/bin/env node

import { fstat } from 'fs';
import { spawnSync } from 'child_process';

import { program, Option } from 'commander';

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
    .option('-o, --output [output path]', 'output file', 'yarn-audit.html')
    .option(
        '-t, --template [ejs path]',
        'ejs template path',
        new URL('../templates/template.ejs', import.meta.url).pathname
    )
    .addOption(
        new Option('--theme [theme name]', 'Bootswatch theme. see https://bootswatch.com/#:~:text=Cerulean')
            .default('materia')
            .choices([
                'cerulean',
                'cosmo',
                'cyborg',
                'darkly',
                'flatly',
                'journal',
                'litera',
                'lumen',
                'lux',
                'materia',
                'minty',
                'morph',
                'pulse',
                'quartz',
                'sandstone',
                'simplex',
                'sketchy',
                'slate',
                'solar',
                'spacelab',
                'superhero',
                'united',
                'vapor',
                'yeti',
                'zephyr',
            ])
    )
    .option('--fatal-exit-code', 'exit with code 1 if vulnerabilities were found', false)
    .parse();

console.info('Checking audit logs...');

let summary: AuditMetadata;
const options = program.opts<Options>();
const vulnerabilities = new Map<string, AuditAdvisor>();

const { stdout } = spawnSync('yarn', ['--version']);

const yarnMajorVersion = Number.parseInt(stdout.toString());

// Determine if cli is piped *in*
fstat(0, (err, stats) => {
    if (!err && !stats.isFIFO()) {
        program.outputHelp();
        process.exit(1);
    }
});

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
