from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def main() -> None:
    raise RuntimeError(
        "online_retrain.py is intentionally disabled. This project does not support safe incremental "
        "retraining from only a new batch because that would overwrite the historical training distribution. "
        "Use train_ai.py and train_malware.py for full retraining instead."
    )


if __name__ == "__main__":
    main()
