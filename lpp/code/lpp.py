import argparse, logging, sys

from pandas import json_normalize

from train.xgb import main as train_main
from utils.database import SetupDatabase
from setup.create_dataframe import CreateDataframe

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++")


def make_frame(collection, outfile=None):
    logger.info("Start of creating dataframe script")
    setup = SetupDatabase()
    cursor = setup.db[collection].find()    
    creator = CreateDataframe(cursor, collection)
    creator.create_dataframe()
    if outfile:
        creator.df.to_pickle(outfile)
    else:
        creator.df.to_pickle("model/df_post_scaling-{}.pickle".format(collection))


def create_parser():
    parser = argparse.ArgumentParser(description="runs all the scripts")
    subparsers = parser.add_subparsers(title="scripts", description='l++ maintenance scripts', help='please read the README.md for more information')
    subparsers.required = True
    subparsers.dest = 'script'

    parser_create_dataframe = subparsers.add_parser('frame', help='create dataframe')
    parser_create_dataframe.add_argument("-c", "--collection", required=True)
    parser_create_dataframe.add_argument('-o', "--outfile", required=False)
    
    parser_train = subparsers.add_parser('train', help="train model")
    parser_train.add_argument('-c', '--collection', required=True)

    return parser
    
def main():
    parser = create_parser()
    try:
        args = parser.parse_args()
    except:
        parser.print_usage()
        return

    if args.script == "frame":
        make_frame(collection=args.collection, outfile=args.outfile)
    elif args.script == "train":
        train_main(args.collection)

if __name__ == "__main__":
    main()

