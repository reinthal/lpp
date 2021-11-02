
import sys, logging, argparse, logging, requests
logging.basicConfig(stream=sys.stdout, level=logging.WARN, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++")

def main():
    logger.info("starting prediction")
    parser = argparse.ArgumentParser(description='Train model with xgb')
    parser.add_argument("-d", "--domain", required=True)
    args = parser.parse_args()
    resp = requests.get(f"http://localhost:8000/predict/{args.domain}")
    logger.warn("Verdict: {verdict}, score: {prediction}, threshold: {threshold}".format(**resp.json()))

if __name__ == "__main__":
    main()