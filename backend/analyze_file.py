import json
import sys

from checks.resilience import analyze


def main(path):
    with open(path) as fh:
        result = analyze(json.load(fh))
    s = result["score"]
    print(f"\nRedundancy score: {s['score']}/100 ({s['label']})  {s['breakdown']}\n")
    for item in result["findings"]:
        print(f"[{item['severity'].upper():7}] {item['message']}")
        print(f"          Fix: {item['suggestion']}")


if __name__ == "__main__":
    main(sys.argv[1])