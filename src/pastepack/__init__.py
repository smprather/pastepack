"""Pack any bytes into text that survives copy/paste, and unpack it again."""

from .codec import PackError, Unpacked, pack, unpack

__all__ = ["PackError", "Unpacked", "pack", "unpack"]
