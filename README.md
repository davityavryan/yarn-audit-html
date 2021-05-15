# yarn-audit-html

[![](https://img.shields.io/david/davityavryan/yarn-audit-html.svg?style=flat-square)](https://david-dm.org/davityavryan/yarn-audit-html/master)
[![](https://img.shields.io/david/dev/davityavryan/yarn-audit-html.svg?style=flat-square)](https://david-dm.org/davityavryan/yarn-audit-html/master?type=dev)
[![](https://img.shields.io/david/peer/davityavryan/yarn-audit-html.svg?style=flat-square)](https://david-dm.org/davityavryan/yarn-audit-html/master?type=peer)
![](https://img.shields.io/github/last-commit/davityavryan/yarn-audit-html.svg?style=flat-square)
[![](https://img.shields.io/snyk/vulnerabilities/npm/yarn-audit-html.svg?style=flat-square)](https://snyk.io/test/npm/yarn-audit-html)
[![](https://img.shields.io/lgtm/alerts/g/davityavryan/yarn-audit-html.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/davityavryan/yarn-audit-html/alerts/)
[![Language grade: JavaScript](https://img.shields.io/lgtm/grade/javascript/g/davityavryan/yarn-audit-html.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/davityavryan/yarn-audit-html/context:javascript)
[![](https://flat.badgen.net/packagephobia/install/yarn-audit-html)](https://packagephobia.now.sh/result?p=yarn-audit-html)
[![Gitter](https://badges.gitter.im/yarn-audit-html/community.svg)](https://gitter.im/yarn-audit-html/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

[![Buy me a coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/davityavryan)

## Generate a HTML report for Yarn Audit

## Install

```bash
yarn global add yarn-audit-html
```

## Usage

To generate a report, run the following:

```bash
yarn audit --json | yarn-audit-html
```

By default, unique vulnerability list will be generated (Grouped by `MODULE_NAME`, `VERSION` and `CWE`) to `yarn-audit.html`

If you want to specify the output file, add the `--output` option:

```bash
yarn audit --json | yarn-audit-html --output report.html
```

You can also fully customize the generated report by providing `--template` option followed by your own EJS template: 

```bash
yarn audit --json | yarn-audit-html --template ./my-awesome-template.ejs
```

If you'd like the generator to exit with non-zero exit code when vulnerabilities are found, you can add the `--fatal-exit-code` option:
```bash
yarn audit --json | yarn-audit-html --fatal-exit-code
```

Inspired by [npm-audit-html](https://github.com/Filiosoft/npm-audit-html) package.

## License

[MIT](LICENSE.md)
