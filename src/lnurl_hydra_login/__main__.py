import asyncio
import logging
import os

from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

from .app import create_app
from .config import Config


def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    config = Config.from_env()
    app = create_app(config)

    hconfig = HypercornConfig()
    hconfig.bind = [f"0.0.0.0:{os.environ.get('PORT', '3000')}"]
    hconfig.accesslog = "-"

    asyncio.run(serve(app, hconfig))


if __name__ == "__main__":
    main()
