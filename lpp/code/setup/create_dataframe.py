# -*- coding: utf-8 -*-
"""
Created on Thu May 14 09:43:19 2020

@author: kog
"""
import sys, os, re, argparse, pickle, logging

import pandas as pd
import numpy as np

from datetime import datetime
from pandas import json_normalize
from sklearn.preprocessing import MinMaxScaler
from sklearn.decomposition import TruncatedSVD

from utils.database import SetupDatabase



NA_fraction_threshold = 0.8

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ create  dataframe")

class TypeNotFoundExcpetion(Exception):
    pass

def save_model(obj, file_path):
    with open(file_path, 'wb') as fp:
        pickle.dump(obj, fp)

def load_model(file_path):
    with open(file_path, 'rb') as fp:
        obj = pickle.load(fp)
    return obj


class CreateDataframe(object):
    """ Creates a dataframe to be used in the DomainPredicter.
    
    Creates a datarame from a mongodb cursor object. Also, it uses the "collection" object to know from which
    collection the models should be loaded from the model folder. For example if this object is initialized with
    collection=domains_dataframe then, xgb model that ends with domains_dataframe will be loaded as well as relevant
    svd transformation and minmax scalers.

    """

    def __init__(self, cursor, collection, load_model=False, n_components=50) -> None:
        self.cursor = cursor
        self.load_model = load_model
        self.n_components = n_components
        self.collection = collection
        super().__init__()
    
    def sort_data(self):
        temp = self.df["ticket_label"]
        self.df.drop(columns="ticket_label", inplace=True)
        self.df.sort_index(axis=1, inplace=True)
        self.df.insert(0, "ticket_label", temp)

    def set_trunc_svd(self, prefix, cols, n_components):
        
        if self.load_model:
            svd, original_cols = load_model("model/svd_{}_{}.pickle".format(prefix, self.collection))
            
            missing_cols = list(set(original_cols) - set(cols))
            self.df.loc[:,missing_cols] = 0 # Impute the missing columns

            extra_cols = list(set(cols) - set(original_cols))
            self.df.drop(columns=extra_cols, inplace=True) # drop the extra columns

            cols = original_cols
            X = self.df.loc[:,cols].values
        else:
            svd = TruncatedSVD(n_components=n_components, n_iter=7, random_state=42)
            X = self.df.loc[:,cols].values
            svd.fit(X)
            save_model((svd, cols), "model/svd_{}_{}.pickle".format(prefix, self.collection))
        
        
        svdDf = svd.transform(X)

        svdDf = pd.DataFrame(
                            data = svdDf, 
                            columns = [f'svd_{prefix}_{i}' for i in range(n_components)]
                        )
        svdDf.index = self.df.index
        self.df.drop(columns=cols, inplace=True)
        self.df = pd.concat([self.df, svdDf], axis=1, sort=False)


    def make_time_objects(self):
        logger.info("Create time objects from timerelated data")
        drop_col = []
        for col in self.df.columns:
            try:
                if "timestamp" in col:
                    logger.debug(f"`timestamp` col: {col}")
                    self.df[col] = pd.to_datetime(self.df[col],unit="s")
                elif "Date" in col and self.df[col].dtype == "object":
                    logger.debug(f"`Date` col and is object: {col}")
                    self.df[col] = pd.to_datetime(self.df[col], infer_datetime_format=False)
                elif "date" in col and self.df[col].dtype == np.float64:
                    logger.debug(f"`date` col and is float {col}")
                    self.df[col] = pd.to_datetime(self.df[col],unit="s")
                elif "date" in col and self.df[col].dtype == np.int64:
                    logger.debug(f"`date` col and is int {col}")
                    self.df[col] = pd.to_datetime(self.df[col],unit="s")
            except Exception:
                logger.warn(f"Exception occurred when make_time_objects for {col}. continueing..")
                drop_col.append(col)
        self.df.drop(columns=drop_col, inplace=True)
    
    def create_tag_string(self):
        logger.info("create tag string")
        tags = [col for col in self.df.select_dtypes("object") if "attributes.tags" in col]

        for col in tags:
            self.df[col].fillna("", inplace=True)
            self.df[col] = self.df[col].str.join(" ")

        self.df["vt.communicating_files.tags"] = self.df[tags].apply(lambda row: ' '.join(row), axis=1)
        self.df.drop(columns=tags, inplace=True)
    
    def keep_same_columns_as_model(self):
        logger.info("Matching columns to model after na drop")
        original_data = pd.read_pickle("model/df_after_na_drop_{}.pickle".format(self.collection))
        new_columns = set(self.df.columns)
        original_columns = set(original_data.columns)
        have_both = original_columns.intersection(new_columns)
        only_in_new = new_columns - original_columns
        only_in_old = original_columns - new_columns
        self.df.drop(columns=list(only_in_new), inplace=True)
        only_in_old = list(only_in_old)
        
        # add nans for old columns
        for col in only_in_old:
            if col in original_data.select_dtypes("datetime64").columns or col in original_data.select_dtypes("timedelta64").columns:
                self.df[col] = np.datetime64('nat')
            elif col in original_data.select_dtypes("object").columns:
                self.df[col] = ""
            elif col in original_data.select_dtypes("float64").columns:
                self.df[col] = 0.0
            elif col in original_data.select_dtypes("int64").columns:
                self.df[col] = 0
            else:
                raise TypeNotFoundExcpetion(f"could not find type of column: {col}") 
        

    def drop_nas(self):
        logger.info("Drop columns with too many missing values")
        columns = self.df.loc[:, self.df.isna().sum() > NA_fraction_threshold * \
                        self.df.shape[0]].columns
        loose = [col for col in columns if col.startswith("vt")]
        logger.info("nr. columns with more than {} nas: {} out of {}".format(
            NA_fraction_threshold,
            len(columns), self.df.shape[1]))
        self.df.drop(columns=loose, inplace=True)
        save_model(self.df.head(1), "model/df_after_na_drop_{}.pickle".format(self.collection))
    
    def create_realtime_tickets_columns(self):
        logger.info("creat realtime ticket data.")
        labels = {
            "ticket_label": [],
            "ticket_first_id": [],
            "ticket_first_date": [],
            "ticket_first_severity": []
        }
        def add_row(label, id, date, severity):
            labels["ticket_label"].append(label)
            labels["ticket_first_id"].append(id)
            labels["ticket_first_date"].append(date)
            labels["ticket_first_severity"].append(severity)

        for ticket, alert_first_date in zip(self.df["tickets"], self.df["alert_first_date"]):
            if not ticket:
                add_row(0, None, None, None)
            else:
                latest_ticket = max(ticket[0]["tickets"], key=lambda x: x["date"])
                # if the latest ticket was written before first real time alert 
                # then label as not reported on in real-time
                if latest_ticket["date"] < alert_first_date:
                    add_row(0, None, None, None)
                else:
                    add_row(1, latest_ticket["id"], latest_ticket["date"], latest_ticket["severity"])
        
        for key in labels.keys():
            self.df.insert(2, key, labels[key])
        logger.info("Inserted the following ticket columns:")
        for col in self.df.columns:
            if "ticket" in col:
                logger.info(col)
        self.df.drop(columns=["tickets"],inplace=True)

    def create_tickets_columns(self):
        logger.info("create ticket data from array")
        tickets = self.df["tickets"]
        labels = {
            "ticket_label": [],
            "ticket_first_id": [],
            "ticket_first_date": [],
            "ticket_first_severity": []
        }

        for row in tickets:
            if not row:
                labels["ticket_label"].append(0)
                labels["ticket_first_id"].append(None)
                labels["ticket_first_date"].append(None)
                labels["ticket_first_severity"].append(None)
            else:
                ticket = min(row[0]["tickets"], key=lambda x: x["date"])
                labels["ticket_label"].append(1)
                labels["ticket_first_id"].append(ticket["id"])
                labels["ticket_first_date"].append(ticket["date"])
                labels["ticket_first_severity"].append(ticket["severity"])
        for key in labels.keys():
            assert len(self.df) == len(labels[key]), "Something went wrong when creating ticket data."

        for key in labels.keys():
            self.df.insert(2, key, labels[key])
        logger.info("Inserted the following ticket columns:")
        for col in self.df.columns:
            if "ticket" in col:
                logger.info(col)
        self.df.drop(columns=["tickets"],inplace=True)

    def create_alerts_columns_including_last_alert(self):
        logger.info("create alert data from array")

        alerts = self.df["alerts"]

        new_alert_data_first = {
            "alert_first_sha": [],
            "alert_first_date": [],
        }


        logger.info("Creating alerts columns FIRST")
        normalized_alerts = []
        for row in alerts:
            
            if row:
                for alert in row:
                    if isinstance(alert["date"], str) and alert["date"].isdigit():
                        alert["date"] = datetime.fromtimestamp(int(alert["date"][:-2]))
                    elif isinstance(alert["date"], str):
                        try:
                            alert["date"] = datetime.strptime(alert["date"], '%Y-%m-%dT%H:%M:%S')
                        except ValueError:
                            logger.warn("Could not parse alert date {} in alert. Replacing with current time.".format(alert["date"], alert["sha"]))
                            alert["date"] = datetime.now()
                alert = min(row, key=lambda x: x["date"])
                normalized_row = list(map(lambda x: x["date"] - alert["date"], row))
                normalized_alerts.append(normalized_row) 
                new_alert_data_first["alert_first_sha"].append(alert["sha"])
                new_alert_data_first["alert_first_date"].append(alert["date"])
            else:
                new_alert_data_first["alert_first_sha"].append("")
                new_alert_data_first["alert_first_date"].append(None)
        for key in new_alert_data_first.keys():
            assert len(new_alert_data_first[key]) == len(self.df), "Something went wrong creating alert data"

        new_alert_data_last = {
            "alert_last_sha": [],
            "alert_last_date": [],
        }


        logger.info("Creating alerts columns LAST")
        for row in alerts:
            
            if row:
                for alert in row:
                    if isinstance(alert["date"], str) and alert["date"].isdigit():
                        alert["date"] = datetime.fromtimestamp(int(alert["date"][:-2]))
                    elif isinstance(alert["date"], str):
                        try:
                            alert["date"] = datetime.strptime(alert["date"], '%Y-%m-%dT%H:%M:%S')
                        except ValueError:
                            logger.warn("Could not parse alert date {} in alert. Replacing with current time.".format(alert["date"], alert["sha"]))
                            alert["date"] = datetime.now()
                alert = max(row, key=lambda x: x["date"])
                new_alert_data_last["alert_last_sha"].append(alert["sha"])
                new_alert_data_last["alert_last_date"].append(alert["date"])
            else:
                new_alert_data_last["alert_last_sha"].append("")
                new_alert_data_last["alert_last_date"].append(None)
        for key in new_alert_data_last.keys():
            assert len(new_alert_data_last[key]) == len(self.df), "Something went wrong creating alert data"

        # Add the new data to data-frame
        for key in new_alert_data_last.keys():
            self.df.insert(2, key, new_alert_data_last[key])

        for key in new_alert_data_first.keys():
                self.df.insert(2, key, new_alert_data_first[key])
        logger.info("Inserting the following ticket colums")
        for col in self.df.columns:
            if "alert_" in col:
                logger.info(col)
        
        self.df.drop(columns=["alerts"],inplace=True)
        self.df["normalized_alerts"] = normalized_alerts



    def create_alerts_columns(self):
        logger.info("create alert data from array")

        alerts = self.df["alerts"]

        new_alert_data = {
            "alert_first_sha": [],
            "alert_first_date": [],
            "alert_first_name": []
        }

        logger.info("Creating alerts columns")
        for row in alerts:
            
            if row:
                for alert in row:
                    if isinstance(alert["date"], str) and alert["date"].isdigit():
                        alert["date"] = datetime.fromtimestamp(int(alert["date"][:-2]))
                    elif isinstance(alert["date"], str):
                        try:
                            alert["date"] = datetime.strptime(alert["date"], '%Y-%m-%dT%H:%M:%S')
                        except ValueError:
                            logger.warn("Could not parse alert date {} in alert. Replacing with current time.".format(alert["date"], alert["sha"]))
                            alert["date"] = datetime.now()
                alert = min(row, key=lambda x: x["date"])
                new_alert_data["alert_first_sha"].append(alert["sha"])
                new_alert_data["alert_first_date"].append(alert["date"])
                new_alert_data["alert_first_name"].append(alert["name"])
            else:
                new_alert_data["alert_first_sha"].append("")
                new_alert_data["alert_first_date"].append(None)
                new_alert_data["alert_first_name"].append("")
        for key in new_alert_data.keys():
            assert len(new_alert_data[key]) == len(self.df), "Something went wrong creating alert data"

        for key in new_alert_data.keys():
                self.df.insert(2, key, new_alert_data[key])
        logger.info("Inserting the following ticket colums")
        for col in self.df.columns:
            if "alert_" in col:
                logger.info(col)
        self.df.drop(columns=["alerts"],inplace=True)

    def drop_cols_no_variance(self):
        logger.info("Drop columns with no variance")
        no_var = []
        for col in self.df.select_dtypes("object").columns:
            if col.startswith("vt"):
                info = self.df[col].describe()
                try:
                    if info.dtype == "object" and info["unique"] == 1:
                        no_var.append(col)
                except Exception:
                    logger.error("error occurred for col:" + col)            
        logger.info("Dropping {} columns with no variance".format(len(no_var)))            
        self.df.drop(columns=no_var, inplace=True)
    
    def rename_index(self):
        logger.info("Rename index to prepare removing meta-data")

        self.df.rename(index=self.df["name"].copy(), inplace=True)

        logger.info("Remove domains with no alert hash")

        self.df = self.df.loc[self.df["alert_first_sha"] !="",]

        logger.info("Remove metadata")

        meta_data = [
            '_id', 
            'name', 
            'alert_first_name', 
            'alert_first_sha',
            'ticket_first_severity',
            'ticket_first_id',
            'domain', 
            'subdomain' 
        ]
        for col in meta_data:    
            try:
                self.df.drop(columns=col, inplace=True)
            except KeyError as e:
                logger.info(f"column not found {col}" )
    def drop_remaining_list_columns(self):
        list_columns = []
        df_objects = self.df.select_dtypes("object")
        for col in df_objects.columns:
            try:
                pd.get_dummies(df_objects.loc[:,col])
            except TypeError as err:
                if "unhashable type: 'list'" in str(err):
                    list_columns.append(col)
        self.df.drop(columns=list_columns, inplace=True)
    
    def get_dummies(self):
        logger.info("Get one-hot encoding")
        dummies = pd.get_dummies(self.df.select_dtypes("object"))

        self.df[dummies.columns] = dummies
        self.df.drop(columns=self.df.select_dtypes("object"), inplace=True)

    def create_time_diff(self):
        """creates time difference relative first alert"""
        logger.info("Create Time Differences Relative First Alert")
        for col in self.df.select_dtypes("datetime64").columns:
            if col.startswith("vt"):
                new_col = "delta_" + col
                self.df[new_col] = self.df[col] - self.df["alert_first_date"]
    
    def keep_processed(self):
        logger.info("Drop Remaining String Data")
        self.df = self.df.select_dtypes(["float64", "int64", "uint8", "timedelta64"])
    
    def rename_bad_column_names(self):
        rename_map = {}
        for col in self.df.columns.values:
            rename_map[col] = re.sub(r"[\[\]\<,]", "_", col)
            
        self.df = self.df.rename(columns=rename_map).copy()

    def make_time_unitless(self):
        logger.info("Create unitless columns from time")
        self.df.loc[:,self.df.select_dtypes("timedelta64").columns] = self.df.select_dtypes("timedelta64") / pd.to_timedelta(1, unit="D")
    
    def compress_data(self):
        logger.info("Compress Various Categorical Features with Truncated SVD")
        http_cols = [col for col in self.df.select_dtypes("uint8") if "attributes.last_http_response_headers.content" in col]
        if http_cols:
            self.set_trunc_svd("url_header_content_http", http_cols, n_components=self.n_components)

        historical_whois_cols = [col for col in self.df.select_dtypes("uint8") if col.startswith("vt.historical_whois")]
        if historical_whois_cols:
            self.set_trunc_svd("historical_whois", historical_whois_cols, n_components=self.n_components)

        domains_categories = [col for col in self.df.select_dtypes("uint8") if col.startswith("vt.domain.data.attributes.categories")]
        if domains_categories:
            self.set_trunc_svd("domain_categories", domains_categories, n_components=self.n_components)

        domain_registrar = [col for col in self.df.select_dtypes("uint8").columns if "vt.domain.data.attributes.registrar" in col]
        if domain_registrar:
            self.set_trunc_svd("domain_registrar", domain_registrar, n_components=self.n_components)

        tld = [col for col in self.df.select_dtypes("uint8").columns if col.startswith("tld")]
        if tld:
            self.set_trunc_svd("tld", tld, n_components=self.n_components)
    
    def calculate_endpoint_statistics(self):
        # Calc stats on all vt native endpoints and attributes, like malicious votes and the like
        regex = r"vt\.(?P<endpoint>.*?)\.data\.\d*?\.attributes\.(?P<attribute>.*)"
        self.calc_stats_on_columns(regex)
        
        # Calc stats on time related vt data for all enpoinds and attributes
        regex = r"delta_vt\.(?P<endpoint>.*?)\.data\.\d*?\.attributes\.(?P<attribute>.*)"
        self.calc_stats_on_columns(regex)

    def calc_stats_on_columns(self, regex):
        """calculate mean, std and count on some rows with mult entries"""
        col_name = "vt_stats.{endpoint}.{attribute}.{statistic}"
        
        matching_columns = [col for col in self.df.columns if re.match(regex, col)]
        logger.info("found {} matching columns. Calculating stats...".format(len(matching_columns)))
        meta_data = [(re.match(regex, col).group(1), re.match(regex, col).group(2)) for col in self.df.columns if re.match(regex, col)]
        meta_data = list(set(meta_data))
        for endpoint, attribute in meta_data:
            
            # get columns matching an <endpoint> with an <attribute>
            end_point_attr_columns = [col for col in self.df.columns if re.match(".*?vt.{0}".format(endpoint), col) and col.endswith(attribute)]
            
            df_subset = self.df[end_point_attr_columns].T.copy(deep=True)

            # calculate stats
            self.df.loc[:,col_name.format(endpoint=endpoint, attribute=attribute, statistic="count")] = df_subset.count()
            self.df.loc[:,col_name.format(endpoint=endpoint, attribute=attribute, statistic="mean")] = df_subset.mean()
            self.df.loc[:,col_name.format(endpoint=endpoint, attribute=attribute, statistic="std")] = df_subset.std()
        
        # drop the old columns when done
        logger.info("Dropping columns. This can take a while...")
        self.df.drop(columns=matching_columns, inplace=True)
    
    def scale_data(self):
        cols = [col for col in self.df.columns if not col.startswith("svd_") and col != "ticket_label"]
        if self.load_model:
            scaler, original_cols = load_model("model/minmax_{}.pickle".format(self.collection))
            
            missing_cols = list(set(original_cols) - set(cols))
            self.df.loc[:, missing_cols] = 0 # Impute the missing columns

            extra_cols = list(set(cols) - set(original_cols))
            self.df.drop(columns=extra_cols, inplace=True) # drop the extra columns
            cols = original_cols
        else:
            scaler = MinMaxScaler()
            scaler.fit(self.df[cols])    
            save_model((scaler, cols), "model/minmax_{}.pickle".format(self.collection))
        self.df[cols] = scaler.transform(self.df[cols])
    
    def json_normalize(self):
        collection = self.collection
        cursor = self.cursor
        logger.info(f"flattening `{collection}`")
        df = json_normalize(cursor)
        self.df = df

    def create_row(self):
        self.json_normalize()
        self.keep_same_columns_as_model()
        self.make_time_objects()
        self.create_tickets_columns()
        self.create_alerts_columns()
        self.rename_index()
        self.drop_remaining_list_columns()
        self.get_dummies()
        self.create_time_diff()
        self.keep_processed()
        self.make_time_unitless() 
        self.compress_data()        
        self.calculate_endpoint_statistics()
        self.scale_data()
        self.sort_data()

    def create_ticket_and_alert_times(self):
        self.json_normalize()
        self.make_time_objects()
        self.create_tickets_columns()
        self.create_alerts_columns_including_last_alert()

    def create_dataframe(self):
        self.json_normalize()
        self.drop_nas()
        self.make_time_objects()
        self.create_tickets_columns()
        self.create_alerts_columns()
        self.drop_cols_no_variance()
        self.rename_index()
        self.get_dummies()
        self.create_time_diff()
        self.keep_processed()
        self.make_time_unitless() 
        self.compress_data()        
        self.calculate_endpoint_statistics()
        self.scale_data()
        self.sort_data()
    
    def create_prediction_summary_dataframe(self):
        self.json_normalize()
        self.df = self.df[self.df["alerts"].notna()]
        self.create_alerts_columns_including_last_alert()
        self.df.drop(columns="normalized_alerts", inplace=True)
        self.create_realtime_tickets_columns()
        self.df["fn"] = self.df["verdict"].isin(["Benign"])  & (self.df["ticket_label"] == 1)
        self.df["fp"] = self.df["verdict"].isin(["Malicious", "Not Sure"]) & (self.df["ticket_label"] == 0)
        self.df = self.df.set_index("name")
