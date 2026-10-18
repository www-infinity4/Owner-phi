import { establish, verify } from "../owner.js";
import { strict as assert } from "assert";

// Basic establishment and verification tests

describe("owner establishment", () => {
  it("creates a valid record", () => {
    const rec = establish({ assetId: "site-123", ownerId: "alice" });
    assert.equal(rec.assetId, "site-123");
    assert.equal(rec.currentOwnerId, "alice");
    assert.equal(rec.version, 1);
    assert.ok(Array.isArray(rec.history));
    assert.equal(rec.history.length, 1);
    assert.equal(rec.history[0].type, "established");
    // verify should not throw
    assert.doesNotThrow(() => verify(rec));
  });
});
