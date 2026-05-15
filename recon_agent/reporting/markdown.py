from __future__ import annotations

import time
from datetime import datetime, timezone

from recon_agent.core.state import AgentState
from recon_agent.llm.prompts import render_reporter


class MarkdownReporter:
    def render(self, state: AgentState) -> str:
        context = {
            "state": state,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
        return render_reporter(context)
