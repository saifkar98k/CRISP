"""
CRISP Agent Swarm 2.0 - Real-Time Streaming Investigation CLI Runner
Reads investigation parameters from stdin (JSON) and writes real-time JSON event lines
to stdout for consumption by Server-Sent Events (SSE) in Express server.ts.
"""

import sys
import json
import logging
from typing import Any, Dict

from services.agents.swarm_service import stream_investigation

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CRISP.StreamRunner")


def main():
    try:
        raw_input = sys.stdin.read().strip()
        if not raw_input:
            input_data = {}
        else:
            input_data = json.loads(raw_input)

        query = input_data.get("query", "").strip()
        target_cve = input_data.get("target_cve") or None
        target_asset = input_data.get("target_asset") or None
        user_role = input_data.get("user_role", "SOC_ANALYST")

        if not query:
            sys.stdout.write(json.dumps({"type": "error", "message": "Investigation query is required."}) + "\n")
            sys.stdout.flush()
            sys.exit(1)

        def event_emitter(event: Dict[str, Any]):
            sys.stdout.write(json.dumps(event) + "\n")
            sys.stdout.flush()

        stream_investigation(
            query=query,
            target_cve=target_cve,
            target_asset=target_asset,
            user_role=user_role,
            on_event=event_emitter,
        )

    except Exception as e:
        logger.exception("Error in stream_runner:")
        sys.stdout.write(json.dumps({"type": "error", "message": str(e)}) + "\n")
        sys.stdout.flush()
        sys.exit(1)


if __name__ == "__main__":
    main()
