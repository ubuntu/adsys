from dataclasses import dataclass
from typing import Any

@dataclass
class entry:
    keyname: str = None
    valuename: str = None
    type: int = None
    data: Any = None
