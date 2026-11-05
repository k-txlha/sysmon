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
