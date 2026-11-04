import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createCanvas, CanvasError, joinSession } from "@github/copilot-sdk/extension";

const extensionDir = dirname(fileURLToPath(import.meta.url));
const servers = new Map();

function servePoster(req, res, posterHtml) {
    const requestUrl = new URL(req.url || "/", "http://127.0.0.1");
    if (requestUrl.pathname !== "/") {
        res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        res.end("Not found");
        return;
    }

    res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
    });
    res.end(posterHtml);
}

const poster = createCanvas({
    id: "agentshield-a2-poster",
    displayName: "AgentShield A2 Poster",
    description: "A print-ready A2 poster explaining AgentShield's architecture, workflow, and evaluation.",
    actions: [
        {
            name: "poster-spec",
            description: "Return the poster's print dimensions and content summary.",
            handler: () => ({
                format: "A2",
                orientation: "portrait",
                dimensions: "420 × 594 mm",
                title: "AgentShield",
                sections: ["Problem", "Defense pipeline", "Security pillars", "Evaluation"],
            }),
        },
    ],
    open: async ({ instanceId }) => {
        if (typeof instanceId !== "string" || instanceId.length === 0) {
            throw new CanvasError("invalid_instance", "A non-empty canvas instance ID is required.");
        }

        const existing = servers.get(instanceId);
        if (existing) {
            return { url: existing.url, title: "AgentShield A2 Poster", status: "ready" };
        }

        const posterHtml = await readFile(join(extensionDir, "poster.html"), "utf8");
        const server = createServer((req, res) => servePoster(req, res, posterHtml));
        await new Promise((resolve, reject) => {
            server.once("error", reject);
            server.listen(0, "127.0.0.1", resolve);
        });

        const address = server.address();
        if (!address || typeof address === "string") {
            server.close();
            throw new CanvasError("server_start_failed", "Unable to determine the poster server address.");
        }

        const entry = {
            server,
            url: `http://127.0.0.1:${address.port}/`,
        };
        servers.set(instanceId, entry);
        return { url: entry.url, title: "AgentShield A2 Poster", status: "ready" };
    },
    onClose: ({ instanceId }) => {
        const entry = servers.get(instanceId);
        if (!entry) {
            return;
        }
        servers.delete(instanceId);
        entry.server.close();
    },
});

await joinSession({ canvases: [poster] });
