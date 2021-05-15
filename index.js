#!/usr/bin/env node

const program = require('commander');
const reporter = require('./lib/reporter');
const pkg = require('./package.json');

program
    .version(pkg.version)
    .option('-o, --output [output]', 'output file')
    .option('-t, --template [ejs file]', 'ejs template file')
    .option('--fatal-exit-code', 'exit with code 1 if vulnerabilities were found')
    .parse();

const genReport = (stdin, output = 'yarn-audit.html', template, fatalExitCode = false) => {
    if (!stdin) {
        console.log('No JSON');
        return process.exit(1);
    }

    const data = stdin.split(/\n/).filter((line) => line !== '');

    let json;
    try {
        json = data.map(JSON.parse);
    } catch (err) {
        console.error('Failed to parse NPM Audit JSON!\n', err);
        return process.exit(1);
    }

    const templateFile = template || `${__dirname}/templates/template.ejs`;

    reporter(json, templateFile, output)
        .then((modifiedData) => {
            if (modifiedData.summary.vulnerabilities > 0) {
                console.log(`Vulnerability snapshot saved at ${output}`);
                if (fatalExitCode) {
                    process.exit(1);
                }
                process.exit(0);
            }

            console.log('No vulnerabilities found.');
            process.exit(0);
        })
        .catch((error) => {
            console.log('An error occurred!');
            console.error(error);
            process.exit(1);
        });
};

const options = program.opts();

let stdin = '';
process.stdin.on('readable', function () {
    const chunk = this.read();

    if (chunk !== null) {
        stdin += chunk;
    }
});
process.stdin.on('end', function () {
    genReport(stdin, options.output, options.template, options.fatalExitCode);
});
