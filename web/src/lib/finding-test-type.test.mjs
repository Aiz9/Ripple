import assert from "node:assert/strict";
import test from "node:test";
import { findingTestType } from "./finding-test-type.ts";

test("classifies finding evidence as static or dynamic", () => {
  assert.equal(findingTestType("Static (jadx decompile). DoLogin writes password to logcat"), "static");
  assert.equal(findingTestType("1) Decompiled CryptoClass.java via apktool"), "static");
  assert.equal(findingTestType("$ curl -sk https://api.example.com/actuator"), "dynamic");
  assert.equal(findingTestType("Hooked with frida at runtime"), "dynamic");
  assert.equal(findingTestType("no markers", 2), "dynamic");
  assert.equal(findingTestType("", 0), null);
  assert.equal(findingTestType(undefined), null);
});
