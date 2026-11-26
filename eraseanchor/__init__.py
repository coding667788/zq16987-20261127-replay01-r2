"""eraseanchor: synthetic crypto-erasure planning, replay and verification."""

__version__ = "1.0.0"
SCHEMA_VERSION = "eraseanchor.case/v1"
PLAN_SCHEMA_VERSION = "eraseanchor.plan/v1"
REPLAY_SCHEMA_VERSION = "eraseanchor.replay/v1"
VERIFY_SCHEMA_VERSION = "eraseanchor.verify/v1"

from .engine import verify_actions  # noqa: E402
from .model import load_json_file, normalize_case  # noqa: E402
from .planner import plan_case  # noqa: E402

__all__ = [
    "__version__",
    "SCHEMA_VERSION",
    "PLAN_SCHEMA_VERSION",
    "REPLAY_SCHEMA_VERSION",
    "VERIFY_SCHEMA_VERSION",
    "load_json_file",
    "normalize_case",
    "plan_case",
    "verify_actions",
]
