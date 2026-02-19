import json
import logging
import nmap
from fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("nmap-mcp")

mcp = FastMCP(
    name="NmapMCP",
    instructions="""
        This server provides nmap analysis tools.
        Call scan() to perform an nmap scan.
    """,
)


def clean(obj):
    """Cleans nmap output, removing empty fields recursively"""
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            v_clean = clean(v)
            if v_clean not in (None, "", {}, []):
                cleaned[k] = v_clean
        return cleaned

    elif isinstance(obj, list):
        cleaned = [clean(v) for v in obj]
        cleaned = [v for v in cleaned if v not in (None, "", {}, [])]
        return cleaned

    else:
        return obj


@mcp.tool
def scan(target: str, port: str) -> str:
    """Performs an unpriviledged nmap scan on the provided target within the given port range"""
    try:
        if not target:
            raise ValueError("Missing target")
        nm = nmap.PortScanner()
        out = json.dumps(clean(nm.scan(target, port)))
        return f"Scan complete. Output: \n{out}"
    except Exception as e:
        msg = f"Error during nmap scan: {str(e)}"
        logger.error(msg)
        return msg
