const fs = require('fs');
const path = require('path');

const ejs = require('ejs');
const { marked } = require('marked');

const bootstrapClassSeverityMap = {
    critical: 'danger',
    high: 'warning',
    moderate: 'secondary',
    low: 'primary',
};
const severitySortPriority = Object.keys(bootstrapClassSeverityMap);

/**
 *
 * @param {object} auditAdvisory -
 * @param {object} auditAdvisory.data -
 * @param {string} auditAdvisory.data.cwe -
 * @param {string} auditAdvisory.data.module_name -
 * @param {object} auditAdvisory.data.advisory -
 * @param {object[]} auditAdvisory.findings -
 * @returns {object[]}
 */
const parseAdvisory = (advisory) => {
    const vulnerabilities = {};

    advisory.findings.forEach((finding) => {
        const version = finding.version;
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
};

const generateReport = (vulnerabilities, summary, options) => {
    options = {
        output: 'yarn-audit.html',
        template: path.resolve(__dirname, '..', 'templates', 'template.ejs'),
        fatalExitCode: false,
        ...options,
    };

    vulnerabilities.sort(
        (left, right) => severitySortPriority.indexOf(left.severity) - severitySortPriority.indexOf(right.severity)
    );

    const report = renderReport(
        {
            reportDate: new Date(),
            vulnerabilities,
            summary: {
                vulnerabilities: Object.values(summary.vulnerabilities).reduce((sum, value) => sum + value, 0),
                totalDependencies: summary.totalDependencies,
            },
        },
        options.template
    );

    writeReport(report, options.output);

    if (vulnerabilities.length > 0) {
        console.info(`Found ${vulnerabilities.length} vulnerabilities. Report is saved in "${options.output}"`);

        if (options.fatalExitCode) {
            process.exit(1);
        }
    } else {
        console.info('Congrats!!! No vulnerabilities found.');
    }

    process.exit(0);
};

const renderReport = (data, template) => {
    const htmlTemplate = fs.readFileSync(template, 'utf8');

    return ejs.render(htmlTemplate, {
        data,
        formatDate: (dateStr) => new Date(dateStr).toLocaleString(),
        severityClass: (severity) => bootstrapClassSeverityMap[severity],
        markdown: marked,
    });
};

const writeReport = (report, output) => {
    fs.writeFileSync(output, report, { encoding: 'utf8' });
};

const bailWithError = (message, error, isFatalExitCode) => {
    console.error(`${message}\n`, error);

    if (isFatalExitCode) {
        process.exit(1);
    }

    process.exit(0);
};

module.exports.bailWithError = bailWithError;
module.exports.generateReport = generateReport;
module.exports.parseAdvisory = parseAdvisory;
module.exports.renderReport = renderReport;
module.exports.writeReport = writeReport;
