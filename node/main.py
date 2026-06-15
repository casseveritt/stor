"""Combined node entry point — runs server (me) and client (them) in one process.

Both FastAPI apps run as independent uvicorn servers sharing the same asyncio
event loop, so they share the interpreter, all loaded modules, and GC overhead
while remaining fully independent at the application level.

Port convention (same as before):
  CONTACC_ME_PORT   (default 28443+N) — server/me, internal only
  CONTACC_THEM_PORT (default 18443+N) — client/them, external via Caddy
"""
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

import uvicorn

log = logging.getLogger("contacc.node")


async def _serve(config: uvicorn.Config) -> None:
    server = uvicorn.Server(config)
    # uvicorn installs its own signal handlers, which fights asyncio.gather —
    # disable them and let our outer process handle shutdown.
    server.install_signal_handlers = lambda: None
    await server.serve()


async def _run(me_config_path: Path, them_config_path: Path,
               me_host: str, me_port: int,
               them_host: str, them_port: int) -> None:
    from server.main import create_app as create_server_app
    from client.main import create_app as create_client_app

    me_app = create_server_app(me_config_path)
    them_app = create_client_app(them_config_path)

    me_cfg = uvicorn.Config(
        me_app, host=me_host, port=me_port,
        proxy_headers=True, forwarded_allow_ips="*",
        log_config=None,
    )
    them_cfg = uvicorn.Config(
        them_app, host=them_host, port=them_port,
        proxy_headers=True, forwarded_allow_ips="*",
        log_config=None,
    )

    loop = asyncio.get_event_loop()

    def _shutdown(signum, frame):
        log.info("Shutting down (signal %d)", signum)
        loop.stop()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    await asyncio.gather(_serve(me_cfg), _serve(them_cfg))


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run a contacc node (server + client in one process)")
    parser.add_argument("me_config",   help="Path to node_config.json   (server/me)")
    parser.add_argument("them_config", help="Path to client_config.json (client/them)")
    parser.add_argument("--me-host",   default="0.0.0.0")
    parser.add_argument("--them-host", default="0.0.0.0")
    parser.add_argument("--me-port",   type=int,
                        default=int(os.environ.get("CONTACC_ME_PORT",   "28443")))
    parser.add_argument("--them-port", type=int,
                        default=int(os.environ.get("CONTACC_THEM_PORT", "18443")))
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    asyncio.run(_run(
        Path(args.me_config),
        Path(args.them_config),
        args.me_host, args.me_port,
        args.them_host, args.them_port,
    ))


if __name__ == "__main__":
    main()
