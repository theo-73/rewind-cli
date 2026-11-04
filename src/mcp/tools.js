import { searchRecords } from '../storage/search.js';
import { runDoctorDiagnostics } from '../storage/doctor.js';
import { McpError, ErrorCodes } from './protocol.js';

const CORE_TOOLS = new Set([
  'rewind_context',
  'rewind_recover',
  'rewind_request_verification',
  'rewind_search'
]);

/**
 * Returns tool definitions array with 2026 safety annotations.
 * Supports filtering by profile ('core' for 4 essential tools, 'full' for all 8).
 *
 * @param {'core' | 'full'} [profile='full']
 * @returns {Array<object>}
 */
export function getToolDefinitions(profile = 'full') {
  const allTools = [
    {
      name: 'rewind_context',
      description: 'Fetch complete forensic context, past failures, and verified fixes for an incident.',
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false
      },
      inputSchema: {
        type: 'object',
        properties: {
          incidentId: {
            type: 'string',
            description: 'Target incident ID or "latest" (defaults to latest observed failure)'
          }
        }
      }
    },
    {
      name: 'rewind_search',
      description: 'Search historical failures and fixes by keyword, error snippet, or command.',
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false
      },
      inputSchema: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description: 'Search terms or error message snippet'
          },
          limit: {
            type: 'number',
            description: 'Limit number of candidate matches (default: 10)'
          }
        },
        required: ['query']
      }
    },
    {
      name: 'rewind_show',
      description: 'Retrieve the raw recorded snapshot and metadata of a specific failure incident.',
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false
      },
      inputSchema: {
        type: 'object',
        properties: {
          incidentId: {
            type: 'string',
            description: 'Incident ID to inspect'
          }
        },
        required: ['incidentId']
      }
    },
    {
      name: 'rewind_history',
      description: 'List recent recorded incidents with verification status and metadata.',
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false
      },
      inputSchema: {
        type: 'object',
        properties: {
          limit: {
            type: 'number',
            description: 'Limit number of entries displayed (default: 10)'
          }
        }
      }
    },
    {
      name: 'rewind_patterns',
      description: 'Empirically group failures by error families, flakiness, and regressions.',
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false
      },
      inputSchema: {
        type: 'object',
        properties: {
          fingerprint: {
            type: 'string',
            description: 'Filter patterns by specific failure fingerprint'
          },
          limit: {
            type: 'number',
            description: 'Maximum pattern families to return'
          }
        }
      }
    },
    {
      name: 'rewind_doctor',
      description: 'Run comprehensive ledger health, cryptographic integrity, and storage checks.',
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false
      },
      inputSchema: {
        type: 'object',
        properties: {}
      }
    },
    {
      name: 'rewind_recover',
      description: 'Record a recovery hypothesis and remediation action for an incident.',
      annotations: {
        readOnlyHint: false,
        idempotentHint: false,
        destructiveHint: false,
        openWorldHint: false
      },
      inputSchema: {
        type: 'object',
        properties: {
          incidentId: {
            type: 'string',
            description: 'Incident ID to recover'
          },
          cause: {
            type: 'string',
            description: 'Suspected root cause'
          },
          change: {
            type: 'string',
            description: 'Remediation action taken'
          },
          verifyCmd: {
            type: 'string',
            description: 'Explicit verification command to prove remediation'
          }
        },
        required: ['incidentId', 'cause', 'change']
      }
    },
    {
      name: 'rewind_request_verification',
      description: 'Request verification plan for an incident. Returns the stored verification command and instructions for host/user approval. Does NOT execute any commands.',
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false
      },
      inputSchema: {
        type: 'object',
        properties: {
          incidentId: {
            type: 'string',
            description: 'Incident ID to request verification for'
          }
        },
        required: ['incidentId']
      }
    }
  ];

  if (profile === 'core') {
    return allTools.filter(t => CORE_TOOLS.has(t.name));
  }
  return allTools;
}

/**
 * Executes an MCP tool call against the Rewind storage engine.
 * @param {string} toolName
 * @param {object} args
 * @param {import('../storage/store.js').StorageEngine} storage
 * @returns {Promise<object>} Tool result { content: [{ type: 'text', text: '...' }], isError?: boolean }
 */
export async function executeTool(toolName, args, storage) {
  function throwParamError(msg) {
    throw new McpError(ErrorCodes.INVALID_PARAMS, msg);
  }

  try {
    let result;

    switch (toolName) {
      case 'rewind_context': {
        if (args.incidentId !== undefined && typeof args.incidentId !== 'string') {
          throwParamError('incidentId must be a string');
        }
        const target = args.incidentId || 'latest';
        if (!storage || typeof storage.getAgentContext !== 'function') {
          throw new McpError(ErrorCodes.INTERNAL_ERROR, 'Storage engine does not support getAgentContext');
        }
        result = await storage.getAgentContext(target, {});
        break;
      }

      case 'rewind_search': {
        if (!args.query) throwParamError('Missing required parameter: "query"');
        if (typeof args.query !== 'string') throwParamError('"query" must be a string');
        if (args.limit !== undefined && typeof args.limit !== 'number') {
          throwParamError('"limit" must be a number');
        }
        const maxLimit = Math.min(Math.max(1, typeof args.limit === 'number' ? args.limit : 5), 10);
        const listRes = storage?.listRecords ? await storage.listRecords() : { records: [] };
        const records = listRes.records || [];
        const rawResults = searchRecords(args.query, records, { limit: maxLimit });
        result = rawResults.map((item) => ({
          ...item,
          record: item.record ? {
            id: item.record.id,
            command: item.record.command,
            fullCommand: item.record.fullCommand?.slice(0, 200),
            status: item.record.status,
            fingerprint: item.record.fingerprint,
            normalizedError: item.record.normalizedError?.slice(0, 300),
            stderr: item.record.stderr?.slice(0, 500),
            recoveryAttemptsCount: item.record.recoveryAttempts?.length || 0
          } : null
        }));
        break;
      }

      case 'rewind_recover': {
        if (!args.incidentId || !args.cause || !args.change) {
          throwParamError('Missing required parameters ("incidentId", "cause", "change")');
        }
        if (typeof args.incidentId !== 'string') throwParamError('"incidentId" must be a string');
        if (typeof args.cause !== 'string') throwParamError('"cause" must be a string');
        if (typeof args.change !== 'string') throwParamError('"change" must be a string');
        if (args.verifyCmd !== undefined && typeof args.verifyCmd !== 'string') {
          throwParamError('"verifyCmd" must be a string');
        }
        if (!storage || typeof storage.addRecoveryAttempt !== 'function') {
          throw new McpError(ErrorCodes.INTERNAL_ERROR, 'Storage engine does not support addRecoveryAttempt');
        }
        result = await storage.addRecoveryAttempt(args.incidentId, {
          cause: args.cause,
          change: args.change,
          verifyCmd: args.verifyCmd,
          status: 'PROPOSED',
          source: 'mcp'
        });
        break;
      }

      case 'rewind_history': {
        if (args.limit !== undefined && typeof args.limit !== 'number') {
          throwParamError('"limit" must be a number');
        }
        if (!storage || typeof storage.listRecords !== 'function') {
          throw new McpError(ErrorCodes.INTERNAL_ERROR, 'Storage engine does not support listRecords');
        }
        result = await storage.listRecords({ limit: args.limit || 10, reverse: true });
        break;
      }

      case 'rewind_show': {
        if (!args.incidentId) throwParamError('Missing required parameter: "incidentId"');
        if (typeof args.incidentId !== 'string') throwParamError('"incidentId" must be a string');
        if (!storage || typeof storage.getRecord !== 'function') {
          throw new McpError(ErrorCodes.INTERNAL_ERROR, 'Storage engine does not support getRecord');
        }
        result = await storage.getRecord(args.incidentId);
        if (!result) {
          return {
            content: [{
              type: 'text',
              text: `Incident #${args.incidentId} not found in ledger.`
            }],
            isError: true
          };
        }
        break;
      }

      case 'rewind_patterns': {
        if (args.fingerprint !== undefined && typeof args.fingerprint !== 'string') {
          throwParamError('"fingerprint" must be a string');
        }
        if (args.limit !== undefined && typeof args.limit !== 'number') {
          throwParamError('"limit" must be a number');
        }
        if (storage && typeof storage.getPatternReport === 'function') {
          result = storage.getPatternReport({
            fingerprint: args.fingerprint || null,
            limit: args.limit || null
          });
        } else {
          result = { patterns: [], patternFamiliesCount: 0 };
        }
        break;
      }

      case 'rewind_doctor': {
        if (storage && typeof storage.diagnoseHealth === 'function') {
          result = storage.diagnoseHealth();
        } else if (storage?.ledgerDir) {
          result = runDoctorDiagnostics(storage.ledgerDir, {});
        } else {
          result = { status: 'HEALTHY', summary: { passed: 0, warnings: 0, failures: 0 } };
        }
        break;
      }

      case 'rewind_verify':                   // Deprecated alias — safe, non-executing
      case 'rewind_request_verification': {
        if (!args.incidentId) throwParamError('Missing required parameter: "incidentId"');
        if (typeof args.incidentId !== 'string') throwParamError('"incidentId" must be a string');

        const record = storage?.getRecord ? storage.getRecord(args.incidentId) : null;
        if (!record) {
          return {
            content: [{
              type: 'text',
              text: `Incident #${args.incidentId} not found in ledger.`
            }],
            isError: true
          };
        }

        let targetAttempt = null;
        if (Array.isArray(record.recoveryAttempts)) {
          for (let i = record.recoveryAttempts.length - 1; i >= 0; i--) {
            if (record.recoveryAttempts[i].verifyCmd) {
              targetAttempt = record.recoveryAttempts[i];
              break;
            }
          }
        }

        const verifyCmd = targetAttempt?.verifyCmd;
        if (!verifyCmd) {
          return {
            content: [{
              type: 'text',
              text: `Incident #${args.incidentId} has no explicit verification command recorded. Record one first using rewind_recover.`
            }],
            isError: true
          };
        }

        // Safety boundary: Return the verification plan for host/user approval.
        // Rewind NEVER executes verification commands through MCP.
        // The host integration or user must execute the command and record the result.
        result = {
          incidentId: record.id,
          attemptId: targetAttempt.id,
          verifyCmd,
          action: 'REQUIRES_HOST_APPROVAL',
          requiresApproval: true,
          execution: 'none',
          instruction: 'Execute this verification command via your host terminal or approval mechanism, then record the result using the CLI.',
          safety: {
            mayAutoExecute: false,
            reason: 'Rewind cannot guarantee user-supplied verification commands are non-destructive. Host integrations own execution approval.'
          }
        };
        break;
      }

      default: {
        throw new McpError(ErrorCodes.METHOD_NOT_FOUND, `Unknown tool: "${toolName}"`);
      }
    }

    return {
      content: [{
        type: 'text',
        text: JSON.stringify(result, null, 2)
      }]
    };
  } catch (error) {
    if (error instanceof McpError && error.code === ErrorCodes.INVALID_PARAMS) {
      throw error; // Protocol-level parameter error to be caught by server.js
    }
    return {
      content: [{
        type: 'text',
        text: `Error: ${error.message || String(error)}`
      }],
      isError: true
    };
  }
}
