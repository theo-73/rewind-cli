import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable, PassThrough } from 'node:stream';
import { parseMessage, createResponse, createErrorResponse, ErrorCodes, McpError } from '../src/mcp/protocol.js';
import { startMcpServer } from '../src/mcp/server.js';
import { getToolDefinitions } from '../src/mcp/tools.js';

function createMockStorage() {
  const records = new Map();
  records.set('1', {
    id: '1',
    command: 'npm',
    args: ['test'],
    fullCommand: 'npm test',
    exitCode: 1,
    status: 'OPEN',
    fingerprint: 'abc123',
    createdAt: new Date().toISOString(),
    stdout: 'Tests run: 1, Failures: 1',
    stderr: 'AssertionError: expected true to be false',
    diagnostic: {
      language: 'node',
      runtime: 'v8',
      errorType: 'AssertionError',
      message: 'expected true to be false',
      stackFrames: [{ function: 'testFn', file: 'test.js', line: 10, column: 5 }]
    },
    recoveryAttempts: [
      {
        id: 1,
        cause: 'Wrong assertion',
        change: 'Fixed assertion logic',
        verifyCmd: 'node -e "process.exit(0)"',
        status: 'PROPOSED',
        verificationRuns: []
      }
    ]
  });

  return {
    getRecord(id) {
      return records.get(String(id)) || null;
    },
    listRecords(opts = {}) {
      const all = Array.from(records.values());
      const res = opts.reverse ? [...all].reverse() : all;
      return { records: res.slice(0, opts.limit || res.length), total: all.length };
    },
    getAgentContext(target) {
      const record = records.get(String(target)) || Array.from(records.values())[0];
      return {
        status: 'success',
        contextSchemaVersion: '1.0.0',
        query: { target },
        observedEvidence: {
          failure: record || null,
          remedies: {
            failedApproaches: [
              { change: 'Bad fix', cause: 'Wrong hypothesis', exitCode: 1 }
            ]
          }
        }
      };
    },
    addRecoveryAttempt(id, data) {
      const record = records.get(String(id));
      if (!record) throw new Error(`Not found: ${id}`);
      const newAttempt = { ...data, id: record.recoveryAttempts.length + 1 };
      record.recoveryAttempts.push(newAttempt);
      return record;
    },
    recordVerificationRun(id, attemptId, runData) {
      const record = records.get(String(id));
      if (!record) throw new Error(`Not found: ${id}`);
      const attempt = record.recoveryAttempts.find(a => a.id === attemptId) || record.recoveryAttempts[0];
      attempt.verificationRuns = attempt.verificationRuns || [];
      attempt.verificationRuns.push(runData);
      if (runData.exitCode === 0) {
        record.status = 'RECOVERED';
        attempt.status = 'VERIFIED';
      } else {
        attempt.status = 'FAILED';
      }
      return record;
    },
    diagnoseHealth() {
      return {
        status: 'HEALTHY',
        summary: { passed: 15, warnings: 0, failures: 0 },
        metrics: { totalRecords: records.size, verifiedRecoveries: 1 }
      };
    },
    getPatternReport() {
      return {
        patternFamiliesCount: 1,
        patterns: [{ fingerprint: 'abc123', count: 1, classifications: [{ type: 'RECURRING_FAILURE' }] }]
      };
    }
  };
}

// Utility to run the server on given inputs and collect outputs
async function runServerWithInput(inputs, storage = createMockStorage(), options = {}) {
  const stdin = Readable.from(inputs.join('\n') + '\n');
  const stdout = new PassThrough();
  const stderr = new PassThrough();

  const outputLines = [];
  stdout.on('data', (chunk) => {
    const lines = chunk.toString().split('\n');
    for (const line of lines) {
      if (line.trim()) outputLines.push(line.trim());
    }
  });

  await startMcpServer(storage, { stdin, stdout, stderr, ...options });

  return outputLines.map(line => JSON.parse(line));
}

test('MCP Protocol Tests', async (t) => {
  await t.test('McpError retains code, message, name, and optional data', () => {
    const err = new McpError(-32002, 'Resource not found', { uri: 'rewind://test' });
    assert.equal(err.name, 'McpError');
    assert.equal(err.code, -32002);
    assert.equal(err.message, 'Resource not found');
    assert.deepEqual(err.data, { uri: 'rewind://test' });
    assert.ok(err instanceof Error);
  });

  await t.test('parseMessage with valid JSON-RPC 2.0 object', () => {
    const msg = parseMessage('{"jsonrpc":"2.0","id":1,"method":"ping"}');
    assert.deepEqual(msg, { jsonrpc: '2.0', id: 1, method: 'ping' });
  });

  await t.test('parseMessage throws McpError on invalid JSON-RPC version', () => {
    assert.throws(() => {
      parseMessage('{"jsonrpc":"1.0","id":1,"method":"ping"}');
    }, (err) => err instanceof McpError && err.code === ErrorCodes.INVALID_REQUEST);
  });

  await t.test('parseMessage throws McpError on malformed JSON', () => {
    assert.throws(() => {
      parseMessage('{"jsonrpc":"2.0",');
    }, (err) => err instanceof McpError && err.code === ErrorCodes.PARSE_ERROR);
  });

  await t.test('createResponse formats correctly', () => {
    const res = createResponse(1, { foo: 'bar' });
    assert.equal(res, '{"jsonrpc":"2.0","id":1,"result":{"foo":"bar"}}');
  });

  await t.test('createErrorResponse formats correctly with data', () => {
    const res = createErrorResponse(1, -32600, 'Invalid', { detail: 'info' });
    assert.equal(res, '{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid","data":{"detail":"info"}}}');
  });
});

test('MCP Server Tests', async (t) => {
  await t.test('initialize handshake negotiates protocol and returns capabilities', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs.length, 1);
    assert.equal(outputs[0].id, 1);
    assert.equal(outputs[0].result.protocolVersion, '2024-11-05');
    assert.ok(outputs[0].result.capabilities.tools);
    assert.ok(outputs[0].result.capabilities.resources);
    assert.ok(outputs[0].result.capabilities.prompts);
    assert.equal(outputs[0].result.serverInfo.name, 'rewind');
  });

  await t.test('initialize negotiates default protocol when client version omitted', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":1,"method":"initialize"}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs.length, 1);
    assert.equal(outputs[0].result.protocolVersion, '2026-07-28');
  });

  await t.test('server/discover negotiates protocol and returns capabilities (2026 revision)', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":100,"method":"server/discover"}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs.length, 1);
    assert.equal(outputs[0].id, 100);
    assert.equal(outputs[0].result.protocolVersion, '2026-07-28');
    assert.ok(outputs[0].result.capabilities.tools);
    assert.equal(outputs[0].result.serverInfo.name, 'rewind');
    assert.equal(outputs[0].result.cacheScope, 'workspace');
    assert.equal(outputs[0].result.ttlMs, 300000);
    assert.equal(outputs[0].result.resultType, 'complete');
    assert.ok(Array.isArray(outputs[0].result.supportedVersions));
    assert.ok(outputs[0].result.supportedVersions.includes('2026-07-28'));
    assert.equal(outputs[0].result._meta.serverInfo.name, 'rewind');
  });

  await t.test('notifications without id MUST NOT generate any response (JSON-RPC 2.0 Invariant)', async () => {
    const inputs = [
      '{"jsonrpc":"2.0","method":"notifications/initialized"}',
      '{"jsonrpc":"2.0","method":"notifications/cancelled"}',
      '{"jsonrpc":"2.0","method":"unknown/notification"}'
    ];
    const outputs = await runServerWithInput(inputs);

    // No response should be emitted for notifications
    assert.equal(outputs.length, 0);
  });

  await t.test('tools/list returns all 8 tool definitions with 2026 safety annotations', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":1,"method":"tools/list"}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs.length, 1);
    const tools = outputs[0].result.tools;
    assert.equal(tools.length, 8);


    const names = tools.map(t => t.name).sort();
    assert.deepEqual(names, [
      'rewind_context',
      'rewind_doctor',
      'rewind_history',
      'rewind_patterns',
      'rewind_recover',
      'rewind_request_verification',
      'rewind_search',
      'rewind_show'
    ]);

    // Verify 2026 tool annotations
    for (const tool of tools) {
      assert.ok(tool.annotations, `Tool ${tool.name} missing annotations`);
      assert.equal(typeof tool.annotations.readOnlyHint, 'boolean');
      assert.equal(typeof tool.annotations.idempotentHint, 'boolean');
      assert.equal(typeof tool.annotations.destructiveHint, 'boolean');
      assert.equal(typeof tool.annotations.openWorldHint, 'boolean');
    }

    // Verify specific safety annotations
    const contextTool = tools.find(t => t.name === 'rewind_context');
    assert.equal(contextTool.annotations.readOnlyHint, true);
    assert.equal(contextTool.annotations.idempotentHint, true);

    const verifyTool = tools.find(t => t.name === 'rewind_request_verification');
    assert.equal(verifyTool.annotations.readOnlyHint, true);
    assert.equal(verifyTool.annotations.openWorldHint, false);
  });

  await t.test('tools/list with profile=core returns only 4 core tools', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":1,"method":"tools/list"}'];
    const outputs = await runServerWithInput(inputs, undefined, { profile: 'core' });

    assert.equal(outputs.length, 1);
    const tools = outputs[0].result.tools;
    assert.equal(tools.length, 4);
    const names = tools.map(t => t.name).sort();
    assert.deepEqual(names, [
      'rewind_context',
      'rewind_recover',
      'rewind_request_verification',
      'rewind_search'
    ]);
  });

  await t.test('tools/call rewind_context returns forensic context', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"rewind_context","arguments":{"incidentId":"1"}}}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].result.resultType, 'complete');
    const content = outputs[0].result.content;
    assert.equal(content.length, 1);
    assert.equal(content[0].type, 'text');
    const parsed = JSON.parse(content[0].text);
    assert.equal(parsed.query.target, '1');
  });

  await t.test('tools/call rewind_search returns matching incidents', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rewind_search","arguments":{"query":"npm"}}}'];
    const outputs = await runServerWithInput(inputs);

    const content = outputs[0].result.content;
    assert.equal(content[0].type, 'text');
  });

  await t.test('tools/call rewind_history returns timeline', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"rewind_history","arguments":{"limit":5}}}'];
    const outputs = await runServerWithInput(inputs);

    const content = outputs[0].result.content;
    const parsed = JSON.parse(content[0].text);
    assert.equal(parsed.records.length, 1);
  });

  await t.test('tools/call rewind_show returns incident on valid ID', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"rewind_show","arguments":{"incidentId":"1"}}}'];
    const outputs = await runServerWithInput(inputs);

    const content = outputs[0].result.content;
    assert.equal(outputs[0].result.isError, undefined);
    const parsed = JSON.parse(content[0].text);
    assert.equal(parsed.id, '1');
  });

  await t.test('tools/call rewind_show returns isError: true on non-existent incident', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"rewind_show","arguments":{"incidentId":"999"}}}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].result.isError, true);
    assert.ok(outputs[0].result.content[0].text.includes('Incident #999 not found'));
  });

  await t.test('tools/call rewind_recover records remediation attempt', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"rewind_recover","arguments":{"incidentId":"1","cause":"bad","change":"fixed"}}}'];
    const outputs = await runServerWithInput(inputs);

    const content = outputs[0].result.content;
    const parsed = JSON.parse(content[0].text);
    assert.equal(parsed.id, '1');
    assert.equal(parsed.recoveryAttempts.length, 2);
  });

  await t.test('tools/call rewind_request_verification returns plan without executing', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"rewind_request_verification","arguments":{"incidentId":"1"}}}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].id, 7);
    const parsed = JSON.parse(outputs[0].result.content[0].text);
    assert.equal(parsed.incidentId, '1');
    assert.equal(parsed.action, 'REQUIRES_HOST_APPROVAL');
    assert.equal(parsed.requiresApproval, true);
    assert.equal(parsed.execution, 'none');
    assert.ok(parsed.verifyCmd);
    assert.equal(parsed.cliCommand, undefined);
    assert.equal(parsed.safety.mayAutoExecute, false);
  });

  await t.test('tools/call rewind_verify (deprecated alias) returns same safe plan', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":70,"method":"tools/call","params":{"name":"rewind_verify","arguments":{"incidentId":"1"}}}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].id, 70);
    const parsed = JSON.parse(outputs[0].result.content[0].text);
    assert.equal(parsed.action, 'REQUIRES_HOST_APPROVAL');
    assert.equal(parsed.execution, 'none');
  });

  await t.test('tools/call rewind_doctor returns ledger health diagnostics', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"rewind_doctor","arguments":{}}}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].id, 8);
    const parsed = JSON.parse(outputs[0].result.content[0].text);
    assert.equal(parsed.status, 'HEALTHY');
  });

  await t.test('tools/call rewind_patterns returns empirical failure patterns', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"rewind_patterns","arguments":{}}}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].id, 9);
    const parsed = JSON.parse(outputs[0].result.content[0].text);
    assert.equal(parsed.patternFamiliesCount, 1);
  });

  await t.test('resources/list returns direct and dynamic resources', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":10,"method":"resources/list"}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].id, 10);
    const resources = outputs[0].result.resources;
    assert.ok(resources.length >= 3);
    const uris = resources.map(r => r.uri);
    assert.ok(uris.includes('rewind://incidents/latest'));
    assert.ok(uris.includes('rewind://doctor/health'));
    assert.ok(uris.includes('rewind://patterns'));
    assert.ok(uris.includes('rewind://incidents/1'));
  });

  await t.test('resources/templates/list returns RFC 6570 URI templates', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":11,"method":"resources/templates/list"}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].id, 11);
    const templates = outputs[0].result.resourceTemplates;
    assert.equal(templates.length, 2);
    assert.equal(templates[0].uriTemplate, 'rewind://incidents/{id}');
    assert.equal(templates[1].uriTemplate, 'rewind://incidents/{id}/evidence');
  });

  await t.test('resources/read returns JSON incident snapshot', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":12,"method":"resources/read","params":{"uri":"rewind://incidents/1"}}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].id, 12);
    const content = outputs[0].result.contents[0];
    assert.equal(content.mimeType, 'application/json');
    const parsed = JSON.parse(content.text);
    assert.equal(parsed.id, '1');
  });

  await t.test('resources/read returns text raw evidence', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":13,"method":"resources/read","params":{"uri":"rewind://incidents/1/evidence"}}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].id, 13);
    const content = outputs[0].result.contents[0];
    assert.equal(content.mimeType, 'text/plain');
    assert.ok(content.text.includes('AssertionError'));
  });

  await t.test('resources/read on non-existent URI returns RESOURCE_NOT_FOUND error', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":14,"method":"resources/read","params":{"uri":"rewind://invalid"}}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].id, 14);
    assert.equal(outputs[0].error.code, ErrorCodes.RESOURCE_NOT_FOUND);
  });

  await t.test('prompts/list returns available prompt templates', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":15,"method":"prompts/list"}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].id, 15);
    const prompts = outputs[0].result.prompts;
    assert.equal(prompts.length, 3);
    const names = prompts.map(p => p.name);
    assert.ok(names.includes('triage-latest'));
    assert.ok(names.includes('verify-fix'));
    assert.ok(names.includes('explain-incident'));
  });

  await t.test('prompts/get triage-latest returns prompt with Negative Memory guidance', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":16,"method":"prompts/get","params":{"name":"triage-latest"}}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].id, 16);
    const text = outputs[0].result.messages[0].content.text;
    assert.ok(text.includes('CRITICAL NEGATIVE MEMORY WARNING'));
    assert.ok(text.includes('Bad fix'));
  });

  await t.test('prompts/get verify-fix returns prompt with verification command', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":17,"method":"prompts/get","params":{"name":"verify-fix","arguments":{"incidentId":"1"}}}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].id, 17);
    const text = outputs[0].result.messages[0].content.text;
    assert.ok(text.includes('node -e "process.exit(0)"'));
    assert.ok(text.includes('rewind_request_verification') || text.includes('rewind_verify'));
  });

  await t.test('unknown method returns METHOD_NOT_FOUND error', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":18,"method":"invalid/method"}'];
    const outputs = await runServerWithInput(inputs);

    assert.equal(outputs[0].error.code, ErrorCodes.METHOD_NOT_FOUND);
  });

  await t.test('ping returns empty object', async () => {
    const inputs = ['{"jsonrpc":"2.0","id":19,"method":"ping"}'];
    const outputs = await runServerWithInput(inputs);

    assert.deepEqual(outputs[0].result, {});
  });
});
