"""Run using a dedicated systemd service/timer, not as a publicly exposed API."""
import asyncio
from app.telegram import deliver_outbox

if __name__ == "__main__":
    print(asyncio.run(deliver_outbox(max_messages=40)))
