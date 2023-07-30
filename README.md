# yarn-audit-html

[![](https://img.shields.io/npm/v/yarn-audit-html?logo=npm)](https://www.npmjs.com/package/yarn-audit-html)
[![](https://img.shields.io/npm/dw/yarn-audit-html?logo=npm)](https://www.npmjs.com/package/yarn-audit-html)
[![](https://snyk.io/test/github/davityavryan/yarn-audit-html/badge.svg)](https://snyk.io/test/github/davityavryan/yarn-audit-html)
![](https://img.shields.io/github/last-commit/davityavryan/yarn-audit-html.svg?style=flat-square&logo=github)
[![](https://img.shields.io/node/v/yarn-audit-html?logo=node.js)](https://github.com/nodejs/release#release-schedule)
[![](https://flat.badgen.net/packagephobia/install/yarn-audit-html?logo=packagephobia)](https://packagephobia.now.sh/result?p=yarn-audit-html)
[![](https://codecov.io/gh/davityavryan/yarn-audit-html/branch/master/graph/badge.svg?token=8HXXAIN7OY)](https://codecov.io/gh/davityavryan/yarn-audit-html)

[![PayPal.me](https://img.shields.io/badge/PayPal-donate-blue?style=for-the-badge&logo=paypal)](https://www.buymeacoffee.com/davityavryan)
[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-donate-yellow?style=for-the-badge&logo=buymeacoffee)](https://www.buymeacoffee.com/davityavryan)

## Generate a HTML report for Yarn Audit

## Install

```bash
yarn add -D yarn-audit-html
# or globally
yarn global add yarn-audit-html
```

## Usage

To generate a report, run the following:

### Yarn V1

```bash
yarn audit --json | yarn yarn-audit-html
```

### Yarn V2+

```bash
yarn npm audit --json | yarn yarn-audit-html
```

By default, unique vulnerability list will be generated (Grouped by `MODULE_NAME`, `VERSION`, `VULNERABLE_VERSIONS`,
`ADVISORY_CREATED_DATE` and `CWE`) to `yarn-audit.html`. This way, even if same version of package has multiple
vulnerabilities, they will be counted.

If you want to specify the output file, add the `--output` option:

```bash
yarn audit --json | yarn yarn-audit-html --output report.html
```

You can also fully customize the generated report by providing `--template` option followed by your own EJS template:

```bash
yarn audit --json | yarn yarn-audit-html --template ./my-awesome-template.ejs
```

There is also a possibility to change default theme(materia) to any of available in
[Bootswatch](https://bootswatch.com/#:~:text=Cerulean) with `--theme` option followed by theme name: p.s. In future
major release default template will change to dark theme.

```bash
yarn audit --json | yarn yarn-audit-html --theme darkly
```

If you'd like the generator to exit with non-zero exit code when vulnerabilities are found, you can add the
`--fatal-exit-code` option:

```bash
yarn audit --json | yarn yarn-audit-html --fatal-exit-code
```

Inspired by [npm-audit-html](https://github.com/Filiosoft/npm-audit-html) package.

See changelog [here](https://github.com/davityavryan/yarn-audit-html/releases).
