import { describe, expect, it } from "vitest";
import { canonicalJSON, sha256Hex, timingSafeEqual } from "../src/util";

describe("timingSafeEqual", () => {
  it("compares equal and unequal strings", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("abc", "abd")).toBe(false);
    expect(timingSafeEqual("abc", "abcd")).toBe(false);
    expect(timingSafeEqual("abcd", "abc")).toBe(false);
    expect(timingSafeEqual("", "")).toBe(true);
    expect(timingSafeEqual("", "a")).toBe(false);
    expect(timingSafeEqual("é", "é")).toBe(false);
  });
});

describe("sha256Hex", () => {
  it("matches the known vector", async () => {
    expect(await sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(await sha256Hex(new Uint8Array([0x61, 0x62, 0x63]))).toBe(await sha256Hex("abc"));
  });
});

describe("canonicalJSON", () => {
  it("sorts keys, drops undefined and is stable", () => {
    expect(canonicalJSON({ b: 1, a: [true, null, { z: "x", y: undefined }] })).toBe('{"a":[true,null,{"z":"x"}],"b":1}');
    expect(canonicalJSON(null)).toBe("null");
    expect(canonicalJSON("s")).toBe('"s"');
    expect(() => canonicalJSON(Number.NaN)).toThrow();
  });
});
