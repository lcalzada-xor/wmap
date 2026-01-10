/**
 * Simple Browser Test Runner
 * Mimics Jest/Mocha syntax for Vanilla JS testing.
 */

export class TestRunner {
    constructor() {
        this.results = document.getElementById('test-results');
        this.summary = document.getElementById('test-summary');
        this.passes = 0;
        this.failures = 0;
    }

    async describe(suiteName, fn) {
        console.group(`%c${suiteName}`, 'color: #0A84FF; font-weight: bold; font-size: 1.1em;');
        this.logSuite(suiteName);
        try {
            await fn();
        } catch (e) {
            console.error(e);
            this.logError(e);
        }
        console.groupEnd();
        this.updateSummary();
    }

    async it(testName, fn) {
        try {
            await fn();
            console.log(`%c  ✔ ${testName}`, 'color: #30D158');
            this.logResult(testName, true);
            this.passes++;
        } catch (e) {
            console.error(`%c  ✘ ${testName}`, 'color: #FF453A', e);
            this.logResult(testName, false, e);
            this.failures++;
        }
    }

    expect(actual) {
        return {
            toBe: (expected) => {
                if (actual !== expected) {
                    throw new Error(`Expected ${actual} to be ${expected}`);
                }
            },
            toEqual: (expected) => {
                const sActual = JSON.stringify(actual);
                const sExpected = JSON.stringify(expected);
                if (sActual !== sExpected) {
                    throw new Error(`Expected ${sActual} to equal ${sExpected}`);
                }
            },
            toBeTruthy: () => {
                if (!actual) throw new Error(`Expected ${actual} to be truthy`);
            },
            toBeFalsy: () => {
                if (actual) throw new Error(`Expected ${actual} to be falsy`);
            },
            toContain: (item) => {
                if (!actual.includes(item)) throw new Error(`Expected ${actual} to contain ${item}`);
            }
        };
    }

    // --- UI Helpers ---

    logSuite(name) {
        if (!this.results) return;
        const el = document.createElement('div');
        el.className = 'suite-header';
        el.textContent = name;
        this.results.appendChild(el);
    }

    logResult(name, passed, error) {
        if (!this.results) return;
        const el = document.createElement('div');
        el.className = `test-result ${passed ? 'pass' : 'fail'}`;
        el.innerHTML = `
            <span class="icon">${passed ? '✔' : '✘'}</span>
            <span class="name">${name}</span>
            ${error ? `<div class="error-msg">${error.message}</div>` : ''}
        `;
        this.results.appendChild(el);
    }

    logError(error) {
        if (!this.results) return;
        const el = document.createElement('div');
        el.className = 'suite-error';
        el.textContent = `Suite Error: ${error.message}`;
        this.results.appendChild(el);
    }

    updateSummary() {
        if (!this.summary) return;
        const total = this.passes + this.failures;
        this.summary.innerHTML = `
            <span class="${this.failures === 0 ? 'success' : 'danger'}">
                ${this.passes} Passed, ${this.failures} Failed
            </span>
        `;
    }
}

export const runner = new TestRunner();
export const describe = runner.describe.bind(runner);
export const it = runner.it.bind(runner);
export const expect = runner.expect.bind(runner);
