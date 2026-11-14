/**
 * Next-Generation Dots AI Platform - Persistent Conversation Repository
 * Milestone 2A: Persistent Conversation System
 *
 * Architectural Mandate:
 * Implements ACID-compliant persistence for conversations and messages using SQLite.
 * Enforces:
 * 1. 100% parameterized SQL.
 * 2. Scope isolation (scope_type, scope_id).
 * 3. Cascade deletion of messages via foreign keys.
 * 4. Client message idempotency index.
 * 5. Strict chronological ordering for conversation messages.
 */

import { randomUUID } from 'node:crypto';
import type { DatabaseManager } from './db.ts';
import type {
  Conversation,
  ConversationMessage,
  ConversationMessageRole,
  ConversationStatus,
  ListConversationsFilter,
  ListMessagesFilter,
  MemoryScopeType,
  ScopeIdentifier
} from '../domain/types.ts';
import { ConversationNotFoundError, ValidationError } from '../domain/errors.ts';

interface ConversationDbRow {
  id: string;
  title: string;
  status: string;
  scope_type: string;
  scope_id: string;
  created_by: string;
  agent_id: string | null;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
}

interface MessageDbRow {
  id: string;
  conversation_id: string;
  role: string;
  content: string;
  name: string | null;
  tool_call_id: string | null;
  tool_calls_json: string | null;
  client_message_id: string | null;
  metadata_json: string | null;
  created_at: string;
}

export interface PersistConversationParams {
  readonly id?: string;
  readonly title: string;
  readonly status?: ConversationStatus;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly createdBy: string;
  readonly agentId?: string | null;
  readonly metadataJson?: string | null;
  readonly createdAt?: string;
  readonly updatedAt?: string;
}

export interface UpdateConversationParams {
  readonly title?: string;
  readonly status?: ConversationStatus;
  readonly agentId?: string | null;
  readonly metadataJson?: string | null;
  readonly updatedAt?: string;
}

export interface PersistMessageParams {
  readonly id?: string;
  readonly conversationId: string;
  readonly role: ConversationMessageRole;
  readonly content: string;
  readonly name?: string | null;
  readonly toolCallId?: string | null;
  readonly toolCallsJson?: string | null;
  readonly clientMessageId?: string | null;
  readonly metadataJson?: string | null;
  readonly createdAt?: string;
}

function mapConversationRow(row: ConversationDbRow): Conversation {
  return {
    id: row.id,
    title: row.title,
    status: row.status as ConversationStatus,
    scopeType: row.scope_type as MemoryScopeType,
    scopeId: row.scope_id,
    createdBy: row.created_by,
    agentId: row.agent_id,
    metadataJson: row.metadata_json,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function mapMessageRow(row: MessageDbRow): ConversationMessage {
  return {
    id: row.id,
    conversationId: row.conversation_id,
    role: row.role as ConversationMessageRole,
    content: row.content,
    name: row.name,
    toolCallId: row.tool_call_id,
    toolCallsJson: row.tool_calls_json,
    clientMessageId: row.client_message_id,
    metadataJson: row.metadata_json,
    createdAt: row.created_at
  };
}

export class ConversationRepository {
  public readonly db: DatabaseManager;

  constructor(db: DatabaseManager) {
    this.db = db;
  }

  /**
   * Executes a callback within a database transaction.
   */
  public transaction<T>(callback: () => T): T {
    return this.db.transaction(callback);
  }

  /**
   * Persists a new conversation.
   */
  public createConversation(params: PersistConversationParams): Conversation {
    const id = params.id ?? randomUUID();
    const now = params.createdAt ?? new Date().toISOString();
    const status = params.status ?? 'ACTIVE';

    if (!params.title || params.title.trim() === '') {
      throw new ValidationError('Conversation title must be a non-empty string.');
    }

    const stmt = this.db.prepare(`
      INSERT INTO conversations (
        id, title, status, scope_type, scope_id, created_by,
        agent_id, metadata_json, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      params.title.trim(),
      status,
      params.scopeType,
      params.scopeId,
      params.createdBy,
      params.agentId ?? null,
      params.metadataJson ?? null,
      now,
      params.updatedAt ?? now
    );

    return {
      id,
      title: params.title.trim(),
      status,
      scopeType: params.scopeType,
      scopeId: params.scopeId,
      createdBy: params.createdBy,
      agentId: params.agentId ?? null,
      metadataJson: params.metadataJson ?? null,
      createdAt: now,
      updatedAt: params.updatedAt ?? now
    };
  }

  /**
   * Retrieves a conversation by its unique ID.
   */
  public getConversationById(id: string): Conversation | null {
    if (!id || typeof id !== 'string') {
      return null;
    }
    const stmt = this.db.prepare('SELECT * FROM conversations WHERE id = ?');
    const row = stmt.get(id.trim()) as unknown as ConversationDbRow | undefined;
    return row ? mapConversationRow(row) : null;
  }

  /**
   * Retrieves a conversation by its unique ID or throws ConversationNotFoundError.
   */
  public getConversationByIdOrThrow(id: string): Conversation {
    const conv = this.getConversationById(id);
    if (!conv) {
      throw new ConversationNotFoundError(id);
    }
    return conv;
  }

  /**
   * Lists conversations within a scope with optional filtering and pagination.
   */
  public listConversations(
    filter: ListConversationsFilter & { scope: ScopeIdentifier }
  ): { conversations: Conversation[]; total: number } {
    const clauses: string[] = ['scope_type = ?', 'scope_id = ?'];
    const params: (string | number)[] = [filter.scope.scopeType, filter.scope.scopeId];

    if (filter.status) {
      clauses.push('status = ?');
      params.push(filter.status);
    }

    if (filter.agentId) {
      clauses.push('agent_id = ?');
      params.push(filter.agentId);
    }

    const whereSql = clauses.join(' AND ');

    const countStmt = this.db.prepare(`SELECT COUNT(*) as count FROM conversations WHERE ${whereSql}`);
    const countRow = countStmt.get(...params) as unknown as { count: number } | undefined;
    const total = countRow ? Number(countRow.count) : 0;

    const limit = Math.max(1, Math.min(filter.limit ?? 50, 200));
    const offset = Math.max(0, filter.offset ?? 0);

    const queryStmt = this.db.prepare(`
      SELECT * FROM conversations
      WHERE ${whereSql}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `);

    const rows = queryStmt.all(...params, limit, offset) as unknown as ConversationDbRow[];
    return {
      conversations: rows.map(mapConversationRow),
      total
    };
  }

  /**
   * Updates conversation metadata, title, agentId, or status.
   */
  public updateConversation(id: string, updates: UpdateConversationParams): Conversation {
    const existing = this.getConversationByIdOrThrow(id);
    const now = updates.updatedAt ?? new Date().toISOString();

    const setClauses: string[] = ['updated_at = ?'];
    const params: (string | null)[] = [now];

    if (updates.title !== undefined) {
      if (!updates.title || updates.title.trim() === '') {
        throw new ValidationError('Conversation title cannot be empty.');
      }
      setClauses.push('title = ?');
      params.push(updates.title.trim());
    }

    if (updates.status !== undefined) {
      setClauses.push('status = ?');
      params.push(updates.status);
    }

    if (updates.agentId !== undefined) {
      setClauses.push('agent_id = ?');
      params.push(updates.agentId);
    }

    if (updates.metadataJson !== undefined) {
      setClauses.push('metadata_json = ?');
      params.push(updates.metadataJson);
    }

    params.push(existing.id);

    const stmt = this.db.prepare(`
      UPDATE conversations
      SET ${setClauses.join(', ')}
      WHERE id = ?
    `);

    stmt.run(...params);
    return this.getConversationByIdOrThrow(existing.id);
  }

  /**
   * Soft-deletes / archives a conversation.
   */
  public archiveConversation(id: string): Conversation {
    return this.updateConversation(id, { status: 'ARCHIVED' });
  }

  /**
   * Hard-deletes a conversation (cascades to all messages via foreign keys).
   */
  public deleteConversation(id: string): boolean {
    const stmt = this.db.prepare('DELETE FROM conversations WHERE id = ?');
    const result = stmt.run(id);
    return Number(result.changes) > 0;
  }

  /**
   * Adds a message to a conversation and touches updated_at.
   */
  public addMessage(params: PersistMessageParams): ConversationMessage {
    const id = params.id ?? randomUUID();
    const now = params.createdAt ?? new Date().toISOString();

    if (!params.content || params.content.trim() === '') {
      throw new ValidationError('Message content cannot be empty.');
    }

    return this.transaction(() => {
      // Ensure conversation exists
      this.getConversationByIdOrThrow(params.conversationId);

      const stmt = this.db.prepare(`
        INSERT INTO conversation_messages (
          id, conversation_id, role, content, name, tool_call_id,
          tool_calls_json, client_message_id, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      stmt.run(
        id,
        params.conversationId,
        params.role,
        params.content,
        params.name ?? null,
        params.toolCallId ?? null,
        params.toolCallsJson ?? null,
        params.clientMessageId ?? null,
        params.metadataJson ?? null,
        now
      );

      // Touch conversation updated_at
      const touchStmt = this.db.prepare('UPDATE conversations SET updated_at = ? WHERE id = ?');
      touchStmt.run(now, params.conversationId);

      return {
        id,
        conversationId: params.conversationId,
        role: params.role,
        content: params.content,
        name: params.name ?? null,
        toolCallId: params.toolCallId ?? null,
        toolCallsJson: params.toolCallsJson ?? null,
        clientMessageId: params.clientMessageId ?? null,
        metadataJson: params.metadataJson ?? null,
        createdAt: now
      };
    });
  }

  /**
   * Retrieves a message by its ID.
   */
  public getMessageById(id: string): ConversationMessage | null {
    if (!id || typeof id !== 'string') {
      return null;
    }
    const stmt = this.db.prepare('SELECT * FROM conversation_messages WHERE id = ?');
    const row = stmt.get(id.trim()) as unknown as MessageDbRow | undefined;
    return row ? mapMessageRow(row) : null;
  }

  /**
   * Retrieves a message by clientMessageId for idempotency deduplication.
   */
  public getMessageByClientId(conversationId: string, clientMessageId: string): ConversationMessage | null {
    if (!conversationId || !clientMessageId) {
      return null;
    }
    const stmt = this.db.prepare(
      'SELECT * FROM conversation_messages WHERE conversation_id = ? AND client_message_id = ?'
    );
    const row = stmt.get(conversationId.trim(), clientMessageId.trim()) as unknown as MessageDbRow | undefined;
    return row ? mapMessageRow(row) : null;
  }

  /**
   * Lists messages for a conversation in chronological order with pagination.
   */
  public listMessages(
    conversationId: string,
    filter: ListMessagesFilter = {}
  ): { messages: ConversationMessage[]; total: number } {
    const countStmt = this.db.prepare(
      'SELECT COUNT(*) as count FROM conversation_messages WHERE conversation_id = ?'
    );
    const countRow = countStmt.get(conversationId) as unknown as { count: number } | undefined;
    const total = countRow ? Number(countRow.count) : 0;

    const limit = Math.max(1, Math.min(filter.limit ?? 50, 500));
    const offset = Math.max(0, filter.offset ?? 0);
    const order = filter.order === 'DESC' ? 'DESC' : 'ASC';

    const queryStmt = this.db.prepare(`
      SELECT * FROM conversation_messages
      WHERE conversation_id = ?
      ORDER BY created_at ${order}
      LIMIT ? OFFSET ?
    `);

    const rows = queryStmt.all(conversationId, limit, offset) as unknown as MessageDbRow[];
    return {
      messages: rows.map(mapMessageRow),
      total
    };
  }
}
