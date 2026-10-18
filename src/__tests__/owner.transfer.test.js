import { establish, transfer, verify } from "../owner.js";
import { createHash } from "crypto";
import { strict as assert } from "assert";

/** Helper to create a valid auth signature for a given message */
function sign(message) {
  return createHash("sha256").update(message).digest("hex");
}

describe("owner transfer contract", () => {
  const assetId = "site-456";
  const seller = "bob";
  const buyer = "carol";
  const baseRecord = establish({ assetId, ownerId: seller });

  it("allows a valid transfer", () => {
    const eventId = "evt-1";
    const authMessage = `${assetId}:${seller}:${eventId}`;
    const receipt = { id: "rcpt-1", amount: 100, paid: true };
    const newRec = transfer(baseRecord, {
      toOwnerId: buyer,
      eventId,
      authMessage,
      authSignature: sign(authMessage),
      settlementReceipt: receipt,
      reason: "sale",
    });
    assert.equal(newRec.currentOwnerId, buyer);
    assert.equal(newRec.version, 2);
    assert.equal(newRec.history.length, 2);
    const last = newRec.history[newRec.history.length - 1];
    assert.equal(last.type, "transfer");
    assert.equal(last.eventId, eventId);
    assert.equal(last.settlementReceipt.paid, true);
    assert.doesNotThrow(() => verify(newRec));
  });

  it("rejects mismatched signature", () => {
    const eventId = "evt-2";
    const authMessage = `${assetId}:${seller}:${eventId}`;
    const badSignature = "invalidsignature";
    const receipt = { id: "rcpt-2", amount: 100, paid: true };
    assert.throws(
      () =>
        transfer(baseRecord, {
          toOwnerId: buyer,
          eventId,
          authMessage,
          authSignature: badSignature,
          settlementReceipt: receipt,
        }),
      (e) => e.code === "auth_invalid_signature"
    );
  });

  it("rejects unpaid settlement", () => {
    const eventId = "evt-3";
    const authMessage = `${assetId}:${seller}:${eventId}`;
    const receipt = { id: "rcpt-3", amount: 100, paid: false };
    assert.throws(
      () =>
        transfer(baseRecord, {
          toOwnerId: buyer,
          eventId,
          authMessage,
          authSignature: sign(authMessage),
          settlementReceipt: receipt,
        }),
      (e) => e.code === "receipt_unpaid"
    );
  });

  it("rejects duplicate eventId", () => {
    const eventId = "evt-dup";
    const authMessage = `${assetId}:${seller}:${eventId}`;
    const receipt = { id: "rcpt-dup", amount: 100, paid: true };
    const first = transfer(baseRecord, {
      toOwnerId: buyer,
      eventId,
      authMessage,
      authSignature: sign(authMessage),
      settlementReceipt: receipt,
    });
    // Attempt a second transfer with the same eventId (different recipient to avoid early no‑op)
    assert.throws(
      () =>
        transfer(first, {
          toOwnerId: "dave",
          eventId,
          authMessage: `${assetId}:${buyer}:${eventId}`,
          authSignature: sign(`${assetId}:${buyer}:${eventId}`),
          settlementReceipt: receipt,
        }),
      (e) => e.code === "duplicate_event"
    );
  });

  it("is idempotent when transferring to the same owner", () => {
    const eventId = "evt-same";
    const authMessage = `${assetId}:${seller}:${eventId}`;
    const receipt = { id: "rcpt-same", amount: 100, paid: true };
    const rec = transfer(baseRecord, {
      toOwnerId: seller,
      eventId,
      authMessage,
      authSignature: sign(authMessage),
      settlementReceipt: receipt,
    });
    // Should return the original record unchanged
    assert.strictEqual(rec, baseRecord);
  });
});
