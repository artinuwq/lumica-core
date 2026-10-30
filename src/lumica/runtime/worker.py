from lumica.infra import ENV_FILE, load_dotenv
from lumica.infra.logging_setup import setup_logging
from lumica.jobs import run_scheduler_forever


def main() -> None:
    load_dotenv(ENV_FILE)
    setup_logging()
    run_scheduler_forever()

