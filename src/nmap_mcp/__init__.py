"""
Nmap MCP Server Package

This package provides an MCP (Model Control Protocol) interface for running nmap scans.
"""

__version__ = "0.1.0"

from .server import mcp


def main():
    mcp.run(transport="http", host="0.0.0.0", port=3001)
