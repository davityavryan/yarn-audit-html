import fs from "node:fs";
import { test, describe, beforeEach, afterEach } from "node:test";

import chai from "chai";
import esmock from "esmock";
import sinon from "sinon";
import sinonChai from "sinon-chai";

import { RawAuditAdvisor } from "./types.js";

chai.should();
chai.use(sinonChai);

let bailWithError: any;
let generateReport: any;
let parseAdvisory: any;
let writeReport: any;
let renderReport: any;

const yarnV1Advisory = JSON.parse(getFixture("yarn1Advisory.json")) as RawAuditAdvisor;

describe("index", () => {
	let processExitStub: sinon.SinonStub;
	let processErrorStub: sinon.SinonStub;
	let consoleInfoMock: sinon.SinonStub;
	let consoleErrorMock: sinon.SinonStub;
	let fsReadFileMock: sinon.SinonStub;
	let fsWriteFileMock: sinon.SinonStub;

	beforeEach(async () => {
		processExitStub = sinon.stub(process, "exit");
		processErrorStub = sinon.stub(process.stderr, "write");
		consoleInfoMock = sinon.mock(console).expects("info");
		consoleErrorMock = sinon.mock(console).expects("error");
		fsWriteFileMock = sinon.stub();
		fsReadFileMock = sinon
			.mock(fs.promises)
			.expects("readFile")
			.returns(
				Promise.resolve(
					'<%= data.vulnerabilities.length %> unique from <%= formatNumber(data.summary.vulnerabilities) %> known vulnerabilities | <%= data.summary.totalDependencies %> dependencies. <%= formatDate(new Date("2021-04-16T00:00:00.000+02:00")) %> - <%= severityClass(data.severity) %>',
				),
			);
		const indexModule = await esmock(
			"./index.ts",
			{
				"node:fs/promises": {
					readFile: fsReadFileMock,
					writeFile: fsWriteFileMock,
				},
			},
			{
				"node:process": {
					exit: processExitStub,
					stderr: { write: processErrorStub },
				},
			},
		);

		bailWithError = indexModule.bailWithError;
		generateReport = indexModule.generateReport;
		parseAdvisory = indexModule.parseAdvisory;
		writeReport = indexModule.writeReport;
		renderReport = indexModule.renderReport;
	});

	afterEach(() => {
		sinon.restore();
	});

	test("parseAdvisory should return vulnerabilities correctly", () => {
		const result = parseAdvisory(yarnV1Advisory);

		result.should.be.deep.equal([
			{
				...yarnV1Advisory,
				key: "async@3.2.0->=3.0.0 <3.2.2-2022-04-07T00:00:17.000Z.CWE-1321",
				paths: [
					"serverless>@serverless/components>@serverless/platform-client-china>archiver>async",
					"serverless-webpack>archiver>async",
				],
				version: "3.2.0",
			},
			{
				...yarnV1Advisory,
				key: "async@3.1.0->=3.0.0 <3.2.2-2022-04-07T00:00:17.000Z.CWE-1321",
				paths: ["async"],
				version: "3.1.0",
			},
		]);
	});

	test("writeReport should work correctly", async () => {
		const codeExample = "reportCode";
		const templatePath = "myTemplate.html";

		await writeReport(templatePath, codeExample);

		fsReadFileMock.should.not.be.called;
		fsWriteFileMock.should.be.calledOnce;

		const result = await renderReport(
			{
				vulnerabilities: [1, 2],
				summary: { vulnerabilities: 123, totalDependencies: 234 },
				date: "2023-01-23T18:54:20.000Z",
				severity: "high",
			},
			"FIXME 222",
		);

		result.should.be.equal(
			"2 unique from 123 known vulnerabilities | 234 dependencies. April 16, 2021 at 12:00:00 AM GMT+2 - warning",
		);

		fsReadFileMock.should.be.calledOnce;
		fsWriteFileMock.should.be.calledOnceWith(templatePath, codeExample);
	});

	test("generateReport should work correctly", async () => {
		const outputPath = "yarnAudit.html";
		const templatePath = "myTemplate.html";

		await generateReport(
			[
				{
					...yarnV1Advisory,
					key: "async@3.2.0->=3.0.0 <3.2.2-2022-04-07T00:00:17.000Z.CWE-1321",
					paths: [
						"serverless>@serverless/components>@serverless/platform-client-china>archiver>async",
						"serverless-webpack>archiver>async",
					],
					version: "3.2.0",
				},
				{
					...yarnV1Advisory,
					key: "async@3.1.0->=3.0.0 <3.2.2-2022-04-07T00:00:17.000Z.CWE-1321",
					paths: ["async"],
					version: "3.1.0",
				},
			],
			{
				vulnerabilities: { info: 0, low: 3, moderate: 83, high: 223, critical: 33 },
				dependencies: 2192,
				devDependencies: 0,
				optionalDependencies: 0,
				totalDependencies: 2192,
			},
			{
				output: outputPath,
				template: templatePath,
				theme: "materia",
				fatalExitCode: true,
			},
		);

		fsReadFileMock.should.be.calledOnce;
		fsWriteFileMock.should.be.calledOnce;
		consoleInfoMock.should.be.calledOnce;
		consoleInfoMock.should.be.calledWithExactly(`Found 2 vulnerabilities. Report is saved in "${outputPath}"`);
		processExitStub.should.be.calledOnce;
		processExitStub.should.be.calledWithExactly(1);
	});

	test("generateReport should return correct code if no vulnerabilities", async () => {
		await generateReport(
			[],
			{
				vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 },
				dependencies: 100,
				devDependencies: 0,
				optionalDependencies: 0,
				totalDependencies: 100,
			},
			{
				output: "yarn-audit.html",
				template: "template.ejs",
				theme: "materia",
				fatalExitCode: true,
			},
		);

		fsReadFileMock.should.be.calledOnce;
		fsWriteFileMock.should.be.calledOnce;
		consoleInfoMock.should.be.calledOnce;
		consoleInfoMock.should.be.calledWithExactly("Congrats!!! No vulnerabilities found.");
		processExitStub.should.be.calledOnce;
		processExitStub.should.be.calledWithExactly(0);
	});

	test("bailWithError should return correct code with isFatalExitCode", async () => {
		bailWithError("message", new Error("message2"), true);

		consoleErrorMock.should.be.calledOnce;
		processExitStub.should.be.calledOnce;
		processExitStub.should.be.calledWithExactly(1);
	});

	test("bailWithError should return correct code", async () => {
		bailWithError("message", new Error("message3"), false);

		consoleErrorMock.should.be.calledOnce;
		processExitStub.should.be.calledOnce;
		processExitStub.should.be.calledWithExactly(0);
	});
});

function getFixture(name: string) {
	return fs.readFileSync(new URL(`../fixtures/${name}`, import.meta.url).pathname, {
		encoding: "utf8",
	});
}
