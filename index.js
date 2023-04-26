#!/usr/bin/env node

const program = require('commander');
const { spawnSync } = require('child_process');

const { bailWithError, generateReport, parseAdvisory } = require('./lib/reporter');
const pkg = require('./package.json');

program
    .version(pkg.version)
    .option('-o, --output [output]', 'output file')
    .option('-t, --template [ejs file]', 'ejs template file')
    .option('--fatal-exit-code', 'exit with code 1 if vulnerabilities were found')
    .parse();

console.log('Checking audit logs...');

let summary = {};
const options = program.opts();
const vulnerabilities = new Map();

const { stdout } = spawnSync('yarn', ['--version']);

const yarnMajorVersion = Number.parseInt(stdout.toString());

let text = '';
process.stdin.on('readable', function () {
    try {
        const chunk = this.read();

        if (chunk !== null) {
            text += chunk;

            const lines = text.split('\n');

            if (lines.length > 1) {
                text = lines.splice(-1, 1)[0];

                lines.forEach((line) => {
                    if (yarnMajorVersion >= 2) {
                        const auditAdvisoryData = JSON.parse(line);

                        Object.values(auditAdvisoryData.advisories).forEach((rawAdvisory) => {
                            advisoryToVulnerabilities(rawAdvisory);
                        });

                        summary = auditAdvisoryData.metadata;
                    } else {
                        const auditAdvisoryData = JSON.parse(line);

                        if (auditAdvisoryData.type === 'auditAdvisory') {
                            advisoryToVulnerabilities(auditAdvisoryData.data.advisory);
                        } else if (auditAdvisoryData.type === 'auditSummary') {
                            summary = auditAdvisoryData.data;
                        }
                    }
                });

                function advisoryToVulnerabilities(advisory) {
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
        bailWithError('Failed to parse YARN Audit JSON!', error, options.fatalExitCode);
    }
});

process.stdin.on('end', function () {
    try {
        generateReport(Array.from(vulnerabilities.values()), summary, options);
    } catch (error) {
        bailWithError(
            `Failed to generate report! Please report this issue to ${pkg.bugs.url}`,
            error,
            options.fatalExitCode
        );
    }
});
