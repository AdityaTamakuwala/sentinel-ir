"""Declarative Playbook & Response Automation Package."""

from app.services.playbook.adapter import (
    ResponseAdapter,
    SimulatedResponseAdapter,
    get_response_adapter,
)
from app.services.playbook.engine import PlaybookEngine
from app.services.playbook.four_eyes import validate_response_approval
from app.services.playbook.loader import PlaybookLoader
from app.services.playbook.registry import StepRegistry, step_registry
from app.services.playbook.templating import evaluate_condition, render_template

__all__ = [
    "PlaybookEngine",
    "PlaybookLoader",
    "ResponseAdapter",
    "SimulatedResponseAdapter",
    "StepRegistry",
    "evaluate_condition",
    "get_response_adapter",
    "render_template",
    "step_registry",
    "validate_response_approval",
]

