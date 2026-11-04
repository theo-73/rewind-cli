import readline from 'node:readline';
import { VERSION } from '../config.js';
import { parseMessage, createResponse, createErrorResponse, ErrorCodes, McpError } from './protocol.js';
import { getToolDefinitions, executeTool } from './tools.js';
import { getResourceList, getResourceTemplates, readResource } from './resources.js';
import { getPromptList, getPrompt } from './prompts.js';
import { redactMcpResult } from '../sanitizer.js';

const SERVER_NAME = 'rewind';
const SUPPORTED_PROTOCOLS = ['2024-11-05', '2025-03-26', '2025-11-25', '2026-07-28'];

/**
 * Starts the MCP server on stdin/stdout.
 * @param {import('../storage/store.js').StorageEngine} storage
 * @param {object} [options]
 * @param {NodeJS.ReadableStream} [options.stdin=process.stdin]
 * @param {NodeJS.WritableStream} [options.stdout=process.stdout]
 * @param {NodeJS.WritableStream} [options.stderr=process.stderr]
 * @returns {Promise<void>}
 */
export async function startMcpServer(storage, options = {}) {
  const input = options.stdin || process.stdin;
  const output = options.stdout || process.stdout;

  const rl = readline.createInterface({ input, crlfDelay: Infinity });

  function send(msg) {
    output.write(msg + '\n');
  }

  for await (const line of rl) {
    if (!line.trim()) continue;

    let msg;
    try {
      msg = parseMessage(line);
    } catch (err) {
      send(createErrorResponse(null, err.code || ErrorCodes.PARSE_ERROR, err.message));
      continue;
    }

    // JSON-RPC 2.0 Invariant: A notification is a Request object without an 'id' member.
    const isNotification = msg.id === undefined || msg.id === null;

    try {
      const result = await handleMessage(msg, storage, options);
      // Notifications expect no response object whatsoever
      if (!isNotification && result !== null) {
        send(createResponse(msg.id, result));
      }
    } catch (err) {
      // JSON-RPC 2.0 Invariant: Server MUST NOT reply to notifications, even on error.
      if (!isNotification) {
        send(createErrorResponse(
          msg.id,
          err.code || ErrorCodes.INTERNAL_ERROR,
          err.message || 'Internal error',
          err.data
        ));
      }
    }
  }
}

async function handleMessage(msg, storage, options = {}) {
  switch (msg.method) {
    case 'initialize': {
      const clientProtocol = msg.params?.protocolVersion;
      const negotiatedVersion = SUPPORTED_PROTOCOLS.includes(clientProtocol)
        ? clientProtocol
        : SUPPORTED_PROTOCOLS[SUPPORTED_PROTOCOLS.length - 1];

      return {
        protocolVersion: negotiatedVersion,
        capabilities: {
          tools: { listChanged: false },
          resources: { subscribe: false, listChanged: false },
          prompts: { listChanged: false }
        },
        serverInfo: {
          name: SERVER_NAME,
          version: VERSION
        }
      };
    }

    case 'server/discover': {
      const clientProtocol = msg.params?.protocolVersion;
      const negotiatedVersion = SUPPORTED_PROTOCOLS.includes(clientProtocol)
        ? clientProtocol
        : SUPPORTED_PROTOCOLS[SUPPORTED_PROTOCOLS.length - 1];

      return {
        protocolVersion: negotiatedVersion,
        supportedVersions: [...SUPPORTED_PROTOCOLS],
        capabilities: {
          tools: { listChanged: false },
          resources: { subscribe: false, listChanged: false },
          prompts: { listChanged: false }
        },
        serverInfo: {
          name: SERVER_NAME,
          version: VERSION
        },
        cacheScope: 'workspace',
        ttlMs: 300000,
        resultType: 'complete',
        _meta: {
          serverInfo: {
            name: SERVER_NAME,
            version: VERSION
          }
        }
      };
    }

    case 'notifications/initialized':
    case 'notifications/cancelled':
      return null; // Fire-and-forget notification

    case 'ping':
      return {};

    // --- TOOLS ---
    case 'tools/list':
      return {
        tools: getToolDefinitions(options.profile || 'full'),
        resultType: 'complete'
      };

    case 'tools/call': {
      const { name, arguments: args } = msg.params || {};
      if (!name) {
        throw new McpError(ErrorCodes.INVALID_PARAMS, 'Missing required parameter: "name"');
      }
      const toolResult = await executeTool(name, args || {}, storage);
      return {
        ...redactMcpResult(toolResult),
        resultType: 'complete'
      };
    }

    // --- RESOURCES ---
    case 'resources/list':
      return {
        resources: await getResourceList(storage),
        resultType: 'complete'
      };

    case 'resources/templates/list':
      return {
        resourceTemplates: getResourceTemplates(),
        resultType: 'complete'
      };

    case 'resources/read': {
      const uri = msg.params?.uri;
      if (!uri) {
        throw new McpError(ErrorCodes.INVALID_PARAMS, 'Missing required parameter: "uri"');
      }
      const resourceResult = await readResource(uri, storage);
      return {
        ...resourceResult,
        resultType: 'complete'
      };
    }

    // --- PROMPTS ---
    case 'prompts/list':
      return {
        prompts: getPromptList(),
        resultType: 'complete'
      };

    case 'prompts/get': {
      const { name, arguments: args } = msg.params || {};
      if (!name) {
        throw new McpError(ErrorCodes.INVALID_PARAMS, 'Missing required parameter: "name"');
      }
      const promptResult = await getPrompt(name, args || {}, storage);
      return {
        ...promptResult,
        resultType: 'complete'
      };
    }

    default:
      throw new McpError(ErrorCodes.METHOD_NOT_FOUND, `Unknown method: "${msg.method}"`);
  }
}
