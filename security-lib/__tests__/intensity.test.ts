/**
 * Network tool intensity floors. The authorization ladder is only meaningful if
 * each tool asks for at least the intensity its effect requires.
 */

import test from "node:test"
import assert from "node:assert/strict"
import { atLeastIntensity } from "../types.ts"
import { NETWORK_INTENSITY_FLOORS, SECURITY_TOOL_IDS } from "../tools/index.ts"
import { ADAPTER_MINIMUM_INTENSITY, SEC_SCAN_MINIMUM_INTENSITY, scanMinimumIntensity } from "../tools/scan.ts"

test("the network tools declare their intensity floors", () => {
  assert.deepEqual(Object.keys(NETWORK_INTENSITY_FLOORS).sort(), ["sec_ports", "sec_recon", "sec_scan"])
  for (const id of Object.keys(NETWORK_INTENSITY_FLOORS)) {
    assert.ok(SECURITY_TOOL_IDS.includes(id as (typeof SECURITY_TOOL_IDS)[number]), `${id} must be registered`)
  }
  assert.equal(NETWORK_INTENSITY_FLOORS.sec_recon, "passive")
  assert.equal(NETWORK_INTENSITY_FLOORS.sec_ports, "safe-active")
  assert.equal(NETWORK_INTENSITY_FLOORS.sec_scan, "safe-active")
})

test("every scanner adapter is no weaker than the tool floor", () => {
  for (const [adapter, floor] of Object.entries(ADAPTER_MINIMUM_INTENSITY)) {
    assert.ok(
      atLeastIntensity(floor, SEC_SCAN_MINIMUM_INTENSITY),
      `${adapter} must not run below the sec_scan floor`,
    )
  }
  assert.equal(scanMinimumIntensity("nmap"), "safe-active")
  assert.equal(scanMinimumIntensity("nmap", "intrusive"), "intrusive")
  assert.equal(scanMinimumIntensity("sqlmap"), "intrusive")
})
