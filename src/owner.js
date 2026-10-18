import { createHash } from "crypto";

// Helper to safely convert values to trimmed strings
const text = (v) => String(v ?? "").trim();

/**
 * Establish a new ownership record.
 * Adds a version field (starting at 1) and an immutable history entry.
 */
export function establish(input = {}) {
  const assetId = text(input.assetId),
    ownerId = text(input.ownerId);
  if (!assetId) throw new TypeError("asset_id_required");
  if (!ownerId) throw new TypeError("owner_id_required");
  const at = input.at || new Date().toISOString();
  return {
    schema: "owner-phi/v1",
    version: 1,
    assetId,
    assetType: text(input.assetType) || "asset",
    projectId: text(input.projectId),
    currentOwnerId: ownerId,
    history: [
      {
        type: "established",
        toOwnerId: ownerId,
        at,
        eventId: "establish-" + cryptoRandomId(),
        reason: "initial",
      },
    ],
  };
}

/**
 * Transfer ownership of an existing record.
 *
 * Required `input` fields:
 *   - toOwnerId: the new owner's identifier
 *   - eventId: a unique identifier for this transfer event (replay protection)
 *   - authMessage: a message signed by the current owner (must contain currentOwnerId and eventId)
 *   - authSignature: SHA‑256 hash of `authMessage`
 *   - settlementReceipt: { id, amount, paid:true }
 * Optional fields: reason, at
 */
export function transfer(record, input = {}) {
  // Basic structural validation of the existing record
  verify(record);

  const toOwnerId = text(input.toOwnerId);
  if (!toOwnerId) throw new TypeError("to_owner_id_required");
  if (toOwnerId === record.currentOwnerId) return record; // idempotent no‑op

  // ---- Replay / duplicate protection ----
  const eventId = text(input.eventId);
  if (!eventId) throw new TypeError("event_id_required");
  if (record.history.some((h) => h.eventId === eventId)) {
    const err = new Error("duplicate_event_id");
    err.code = "duplicate_event";
    throw err;
  }

  // ---- Authorization validation ----
  const authMessage = text(input.authMessage);
  const authSignature = text(input.authSignature);
  if (!authMessage) throw new TypeError("auth_message_required");
  if (!authSignature) throw new TypeError("auth_signature_required");

  // Simple ownership proof: the message must contain the current owner and the eventId
  if (!authMessage.includes(record.currentOwnerId) || !authMessage.includes(eventId)) {
    const err = new Error("auth_message_mismatch");
    err.code = "auth_invalid_message";
    throw err;
  }
  // Verify the signature is a SHA‑256 hash of the message
  const expectedSig = createHash("sha256").update(authMessage).digest("hex");
  if (authSignature !== expectedSig) {
    const err = new Error("auth_signature_invalid");
    err.code = "auth_invalid_signature";
    throw err;
  }

  // ---- Settlement receipt validation ----
  const receipt = input.settlementReceipt;
  if (!receipt || typeof receipt !== "object") {
    const err = new Error("settlement_receipt_missing");
    err.code = "receipt_missing";
    throw err;
  }
  if (receipt.paid !== true) {
    const err = new Error("settlement_not_paid");
    err.code = "receipt_unpaid";
    throw err;
  }

  // ---- Build the new immutable record ----
  const newVersion = (record.version ?? 1) + 1;
  const at = input.at || new Date().toISOString();
  const reason = text(input.reason) || "transfer";

  const newRecord = {
    ...record,
    version: newVersion,
    currentOwnerId: toOwnerId,
    history: [
      ...record.history,
      {
        type: "transfer",
        fromOwnerId: record.currentOwnerId,
        toOwnerId,
        eventId,
        reason,
        at,
        authMessage,
        authSignature,
        settlementReceipt: receipt,
      },
    ],
  };

  // Verify the newly built record before returning
  verify(newRecord);
  return newRecord;
}

/**
 * Verify the integrity of an ownership record.
 * Checks schema, required fields, version, and uniqueness of eventIds.
 */
export function verify(record) {
  if (!record || record.schema !== "owner-phi/v1")
    throw new TypeError("invalid_owner_record");
  if (!text(record.assetId)) throw new TypeError("invalid_asset_id");
  if (!text(record.currentOwnerId))
    throw new TypeError("invalid_current_owner_id");
  if (typeof record.version !== "number" || record.version < 1)
    throw new TypeError("invalid_version");
  if (!Array.isArray(record.history))
    throw new TypeError("invalid_history_array");

  const seen = new Set();
  for (const entry of record.history) {
    if (!entry.type) throw new TypeError("history_entry_missing_type");
    if (entry.eventId) {
      if (seen.has(entry.eventId)) {
        const err = new Error("duplicate_event_id_in_history");
        err.code = "duplicate_event";
        throw err;
      }
      seen.add(entry.eventId);
    }
  }
  return true;
}

/** Simple random identifier generator for internal events (non‑cryptographic). */
function cryptoRandomId() {
  return Math.random().toString(36).substring(2, 10);
}
