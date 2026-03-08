from lumica.infra import ENV_FILE, load_dotenv
from lumica.jobs import run_scheduler_forever


def main() -> None:
    load_dotenv(ENV_FILE)
    run_scheduler_forever()

