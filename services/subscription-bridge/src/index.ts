import { createBridge } from "./server.ts";
import { buildRunners } from "./runners.ts";

const host = process.env.YABANIN_BRIDGE_HOST ?? "127.0.0.1";
const port = Number(process.env.YABANIN_BRIDGE_PORT ?? "8091");
const launchRoot = process.env.YABANIN_DELEGATION_WORKSPACE ?? process.cwd();

const runners = await buildRunners();
const bridge = createBridge({ host, port, runners, launchRoot });
const { url } = await bridge.listen();
console.log(JSON.stringify({ msg: "subscription-bridge listening", url }));
