"""
This is the heart of l++ - the main script.

TODO: Implement alert fetch.
TODO: Implement vt fetch.
TODO: Implement health checks.

"""
import argparse, logging, sys

from train.xgb import main as train_main
from utils.database import SetupDatabase
from unittests.validate import main as validate_main
from setup.rebuild import rebuild
from setup.create_indeces import main as create_indeces_main
from setup.snow_export import main as snow_export_main
from setup.splunk_export import main as splunk_export_main
from setup.create_dataframe import CreateDataframe
from setup.create_domains_dataframe_collection import main as create_domains_dataframe_main
from setup.update_domains import main as update_domains_main

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++")


def make_frame(collection, outfile=None, frame_type="model"):
    logger.info("Start of creating dataframe script")
    setup = SetupDatabase()
    cursor = setup.db[collection].find()    
    creator = CreateDataframe(cursor, collection)
    if frame_type == "model":
        creator.create_dataframe()
        outfile = "model/df_post_scaling-{}.pickle".format(collection)
    elif frame_type == "ticket":
        creator.create_ticket_and_alert_times()
    else:
        logger.warn(f"non-defined frame_type: {frame_type}")
    creator.df.to_pickle(outfile)

def create_parser():
    parser = argparse.ArgumentParser(description="runs all the scripts")
    subparsers = parser.add_subparsers(title="scripts", description='l++ maintenance scripts', help='please read the README.md for more information')
    subparsers.required = True
    subparsers.dest = 'script'

    parser_make_dataframe = subparsers.add_parser('make', help='make collection')
    parser_make_dataframe.add_argument("-c", "--collection", required=True)
    

    parser_create_dataframe = subparsers.add_parser('frame', help='create dataframe')
    parser_create_dataframe.add_argument("-c", "--collection", required=True)
    parser_create_dataframe.add_argument('-o', "--outfile", required=True)
    parser_create_dataframe.add_argument('-t', "--type", required=False)

    parser_train = subparsers.add_parser('train', help="train model")
    parser_train.add_argument('-c', '--collection', required=True)

    subparsers.add_parser('validate', help="runs diagnostic tests on data")
    subparsers.add_parser('setup', help="Set up us the db indeces")
    subparsers.add_parser('rebuild', help="reqbuilds `domains_realtime` collection to include full analysis from get_prediction.")

    parser_snow = subparsers.add_parser('snow', help="Fetch SNOW incidents")
    parser_snow.add_argument("-u", "--update", action='store_true')

    parser_splunk =  subparsers.add_parser('splunk', help='Export alert data from Splunk')
    parser_splunk.add_argument("-s", "--startdate", required=True)
    parser_splunk.add_argument("-e", "--enddate", required=True)
    parser_splunk.add_argument("-u", "--user", required=True)
    parser_splunk.add_argument("-p", "--password", required=False)
    parser_splunk.add_argument("-c", "--collection", required=True)

    parser_update = subparsers.add_parser('update', help="Update collection with new alerts and incidents")
    parser_update.add_argument("-d", "--domains", help="The collection to output documents to.", required=False)
    parser_update.add_argument("-a", "--alerts", help="The input collection.", required=False)

    return parser
    
def main():
    parser = create_parser()
    try:
        args = parser.parse_args()
    except:
        parser.print_usage()
        return
    if args.script == "make":
        create_domains_dataframe_main(args.collection)
    elif args.script == "frame":
        make_frame(collection=args.collection, outfile=args.outfile, frame_type=args.type)
    elif args.script == "rebuild":
        rebuild()
    elif args.script == "train":
        train_main(args.collection)
    elif args.script == "setup":
        create_indeces_main()
    elif args.script == "snow":
        snow_export_main(args.update)
    elif args.script == "update":
        try:
            update_domains_main(domains_collection=args.domains, alerts_collection=args.alerts)
        except AttributeError:
            update_domains_main()
            
    elif args.script == "validate":
        validate_main()
    elif args.script == "splunk":
        splunk_export_main(args)



if __name__ == "__main__":
    main()

