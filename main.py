"""Entry point: starts the Mailpit polling interceptor in the background and
serves the Flask dashboard / simulated end-user notification UI."""
import logging

from app.config import config
from app.email.interceptor import start_background_poller
from app.web import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


def main():
    start_background_poller()
    app = create_app()
    logger = logging.getLogger("main")
    logger.info("Dashboard: http://%s:%s/", "localhost", config.APP_PORT)
    logger.info("Mailpit UI expected at: http://%s:%s/", config.MAILPIT_HOST, config.MAILPIT_UI_PORT)
    app.run(host=config.APP_HOST, port=config.APP_PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
