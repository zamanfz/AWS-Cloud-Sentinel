from backend.ai.anomaly_model import CloudSentinelAnomalyModel


def main():
    model = CloudSentinelAnomalyModel()

    result = model.train()

    print("\n=== CloudSentinel ML Model ===")
    print(f"Algorithm: {result['algorithm']}")
    print(f"Training samples: {result['training_samples']}")
    print(f"Features: {result['features']}")
    print(f"Model saved: {result['model_path']}")


if __name__ == "__main__":
    main()
