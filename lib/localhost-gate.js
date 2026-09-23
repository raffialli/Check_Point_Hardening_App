import { BlockList, isIP } from "node:net";

// The only decision for whether one-click update may run.
// A later release channel can reuse this gate; do not copy the check elsewhere.
const loopback = new BlockList();
loopback.addSubnet("127.0.0.0", 8, "ipv4");
loopback.addAddress("::1", "ipv6");

export const LOCALHOST_ONLY_LABEL = "localhost only";

export const LOCALHOST_ONLY_DETAIL = "One-click update fast-forwards this checkout from origin/main, may run npm install, and restarts the app. It is allowed only when the browser is connected to this machine through localhost (127.0.0.1 or ::1). A page opened by another hostname, a LAN address, or from another computer cannot change files or restart the server.";

export function hostnameFromHostHeader(hostHeader) {
  const value = String(hostHeader || "").trim().toLowerCase();
  if (!value) return "";
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    return end === -1 ? "" : value.slice(1, end);
  }
  return value.replace(/:\d+$/, "");
}

export function isLoopbackAddress(address) {
  let value = String(address || "").trim().toLowerCase();
  if (!value) return false;
  if (value === "localhost") return true;
  if (value.startsWith("::ffff:")) {
    const mapped = value.slice("::ffff:".length);
    if (isIP(mapped) === 4) value = mapped;
  }
  const family = isIP(value);
  if (!family) return false;
  return loopback.check(value, family === 4 ? "ipv4" : "ipv6");
}

export function assessLocalhostGate({ hostHeader = "", remoteAddress = "" } = {}) {
  const host = hostnameFromHostHeader(hostHeader);
  const hostIsLoopback = isLoopbackAddress(host);
  const remoteIsLoopback = isLoopbackAddress(remoteAddress);
  const allowed = hostIsLoopback && remoteIsLoopback;
  return {
    allowed,
    label: LOCALHOST_ONLY_LABEL,
    detail: LOCALHOST_ONLY_DETAIL,
    host,
    remoteAddress: String(remoteAddress || "")
  };
}
