import fs from 'node:fs';
import { Readable } from 'node:stream';
import childProcess, { SpawnSyncReturns } from 'node:child_process';
import { describe, test, beforeEach, afterEach } from 'node:test';

import chai from 'chai';
import esmock from 'esmock';
import sinon from 'sinon';
import sinonChai from 'sinon-chai';

chai.should();
chai.use(sinonChai);

const yarnV1Audit = getFixture('yarn1.jsonl');
const yarnV2Audit = getFixture('yarn2.json');
const yarnV3Audit = getFixture('yarn3.json');

describe('cli', () => {
    let fstatSync: sinon.SinonStub;
    let processExit: sinon.SinonStub;
    let spawnSync: sinon.SinonStub;
    let processStdout: sinon.SinonSpy;
    let processStderr: sinon.SinonSpy;
    let programOutputHelp: sinon.SinonStub;
    let consoleInfo: sinon.SinonStub;
    let bailWithError: sinon.SinonStub;
    let generateReport: sinon.SinonStub;
    let programMock: Record<
        string,
        sinon.SinonStub | (() => typeof programMock) | (() => Record<string, string | boolean>)
    >;

    const stdinMock1 = new Readable({
        read() {
            this.push(yarnV1Audit);
            this.push(null);
        },
    });

    const stdinMock2 = new Readable({
        read() {
            this.push(yarnV2Audit);
            this.push(null);
        },
    });

    const stdinMock3 = new Readable({
        read() {
            this.push(yarnV3Audit);
            this.push(null);
        },
    });

    beforeEach(async () => {
        fstatSync = sinon.stub().returns({
            isFIFO: () => true,
        });
        spawnSync = sinon.stub(childProcess, 'spawnSync').returns({ stdout: '1.0.0' } as SpawnSyncReturns<string>);
        processExit = sinon.stub(process, 'exit');
        processStdout = sinon.spy(process.stdout, 'write');
        processStderr = sinon.spy(process.stderr, 'write');
        programOutputHelp = sinon.stub();
        consoleInfo = sinon.stub(console, 'info');
        bailWithError = sinon.stub();
        generateReport = sinon.stub();
        programMock = {
            opts: () => ({
                output: '',
                template: '',
                theme: 'materia',
                fatalExitCode: true,
            }),
            option: () => programMock,
            addOption: () => programMock,
            parse: () => programMock,
            outputHelp: programOutputHelp,
        };
    });

    test('should work properly when executed with no piped in data', async () => {
        fstatSync.returns({
            isFIFO: () => false,
        });

        const run = await mockModule();

        await run([], process.stdin);

        consoleInfo.should.be.calledOnce;
        fstatSync.should.be.calledOnce;
        programOutputHelp.should.be.calledOnce;
        processExit.should.be.calledOnce.and.calledWithExactly(1);
    });

    test('should work properly when executed without arguments and with piped in data', async () => {
        const run = await mockModule();

        await run([], stdinMock1);

        consoleInfo.should.be.calledOnce;
        fstatSync.should.be.calledOnce;
        processStderr.should.not.be.called;
        spawnSync.should.be.calledOnce;
        // generateReport.should.be.called;
    });

    test('should work properly for yarn v2', async () => {
        spawnSync.returns({ stdout: '2.0.0' });

        const run = await mockModule();

        await run([], stdinMock2);

        consoleInfo.should.be.calledOnce;
        fstatSync.should.be.calledOnce;
        processStderr.should.not.be.called;
        processExit.should.not.be.called;
    });

    test('should work properly for yarn v3', async () => {
        spawnSync.returns({ stdout: '3.0.0' });

        const run = await mockModule();

        await run([], stdinMock3);

        consoleInfo.should.be.calledOnce;
        fstatSync.should.be.calledOnce;
        processStderr.should.not.be.called;
        processExit.should.not.be.called;
    });

    // TODO: enable
    test('should work properly there is an error in generation', { skip: true }, async () => {
        generateReport.returns(() => Promise.reject(''));

        const run = await mockModule();

        await run([], stdinMock1);

        consoleInfo.should.be.calledOnce;
        fstatSync.should.be.calledOnce;
        fstatSync.should.be.calledOnce;
        generateReport.should.be.calledOnce;
        bailWithError.should.be.calledOnce;
    });

    afterEach(() => {
        sinon.restore();
    });

    async function mockModule() {
        return (
            await esmock(
                './cli.ts',
                {
                    './index.ts': {
                        bailWithError,
                        generateReport,
                    },
                },
                {
                    'node:child_process': { spawnSync },
                    'node:fs': {
                        fstatSync,
                    },
                    'node:process': { exit: processExit, stdout: processStdout },
                    commander: {
                        program: programMock,
                    },
                }
            )
        ).run;
    }
});

function getFixture(name: string) {
    return fs.readFileSync(new URL(`../fixtures/${name}`, import.meta.url).pathname, {
        encoding: 'utf8',
    });
}
