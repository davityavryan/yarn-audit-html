const fs = require('fs');
const ejs = require('ejs');
const marked = require('marked');
const { promisify } = require('util');

const bootstrapClassSeverityMap = {
    critical: 'danger',
    high: 'warning',
    moderate: 'secondary',
    low: 'primary',
};
const severitySortPriority = Object.keys(bootstrapClassSeverityMap);

const generateTemplate = async (data, template) => {
    try {
        const readFile = promisify(fs.readFile);
        const htmlTemplate = await readFile(template, 'utf8');

        return ejs.render(htmlTemplate, {
            ...data,
            formatDate: (dateStr) => (new Date(dateStr)).toLocaleString(),
            severityClass: (severity) => bootstrapClassSeverityMap[ severity ],
            markdown: marked,
        });
    } catch (err) {
        throw err;
    }
};

const writeReport = async (report, output) => {
    try {
        const writeFile = promisify(fs.writeFile);
        await writeFile(output, report);
    } catch (err) {
        throw err;
    }
};

const modifyData = async (data, showUnique, baseTarget) => {
    const auditAdvisories = data.filter((vulnerability) => vulnerability.type === 'auditAdvisory');
    const reportDate = new Date();
    const summaryData = data.pop().data;
    const summary = {
        ...summaryData,
        vulnerabilities: Object.values(summaryData.vulnerabilities).reduce((sum, next) => (sum + next), 0),
    };

    let vulnerabilities = auditAdvisories.map((vulnerability) => ({
        ...vulnerability.data.advisory,
        paths: [vulnerability.data.resolution.path],
    }));

    if (showUnique) {
        const vulnerabilitiesSet = {};

        vulnerabilities.forEach((vulnerability) => {
            vulnerability.findings.forEach((finding) => {
                const key = `${vulnerability.module_name}@${finding.version}`;

                if (!(key in vulnerabilitiesSet)) {
                    vulnerabilitiesSet[key] = {
                        ...vulnerability,
                        paths: finding.paths,
                        version: finding.version,
                    };
                }
            });
        });

        vulnerabilities = Object.values(vulnerabilitiesSet);
    }

    vulnerabilities.sort((left, right) => (
        severitySortPriority.indexOf(left.severity) - severitySortPriority.indexOf(right.severity))
    );

    return {
        showUnique,
        reportDate,
        vulnerabilities,
        summary,
        baseTarget,
    };
};

module.exports = async (data, templateFile, outputFile, showUnique, baseTarget) => {
    try {
        const modifiedData = await modifyData(data, showUnique, baseTarget);
        const report = await generateTemplate(modifiedData, templateFile);

        await writeReport(report, outputFile);
    } catch (err) {
        console.error(err);
    }
};
