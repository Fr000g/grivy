"""
终端配色工具。
采用 Catppuccin Mocha 调色盘，提供基础的 24-bit ANSI 前景色渲染。
"""

from typing import Dict, Tuple

# Catppuccin Mocha 调色盘（仅需少量色值）
_PALETTE: Dict[str, Tuple[int, int, int]] = {
    "text": (205, 214, 244),
    "subtext0": (166, 173, 200),
    "subtext1": (180, 190, 214),
    "blue": (137, 180, 250),
    "lavender": (180, 190, 254),
    "peach": (250, 179, 135),
    "teal": (148, 226, 213),
}

RESET = "\033[0m"


def _rgb_code(name: str) -> str:
    rgb = _PALETTE.get(name)
    if not rgb:
        return ""
    r, g, b = rgb
    return f"\033[38;2;{r};{g};{b}m"


def color_text(text: str, color: str) -> str:
    """按给定颜色渲染文本；若颜色未定义则原样返回。"""
    code = _rgb_code(color)
    return f"{code}{text}{RESET}" if code else text


def dim_text(text: str) -> str:
    """使用次级文字色（浅灰）淡化文本。"""
    return color_text(text, "subtext0")
