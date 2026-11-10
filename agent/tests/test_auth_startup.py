from unittest.mock import MagicMock, patch

import pytest

from agent.main import Agent
from agent.utils.transport import AgentAuthenticationError


def test_agent_does_not_enter_operation_without_credentials():
    agent = Agent.__new__(Agent)
    agent.buffer = MagicMock()
    with (
        patch("agent.main.get_current_token", return_value=""),
        patch("agent.main.start_token_renewal") as start_renewal,
        patch("agent.main.stop_token_renewal") as stop_renewal,
    ):
        with pytest.raises(AgentAuthenticationError):
            agent.run()
    start_renewal.assert_not_called()
    stop_renewal.assert_called_once()
    agent.buffer.close.assert_called_once()


def test_agent_keeps_collecting_after_authentication_rejection():
    agent = Agent.__new__(Agent)
    agent.buffer = MagicMock()
    agent.collect_envelopes = MagicMock(return_value=[{"event_id": "evt-1"}])
    with (
        patch("agent.main.get_current_token", return_value="present"),
        patch("agent.main.start_token_renewal") as start_renewal,
        patch("agent.main.stop_token_renewal") as stop_renewal,
        patch("agent.main.ship_to_backend") as ship,
        patch("agent.main.time.sleep", side_effect=KeyboardInterrupt),
    ):
        agent.run()

    start_renewal.assert_called_once()
    agent.collect_envelopes.assert_called_once()
    ship.assert_called_once_with([{"event_id": "evt-1"}])
    stop_renewal.assert_called_once()
    agent.buffer.close.assert_called_once()
