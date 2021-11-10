import sys, logging, pickle, logging
import shap
import pandas as pd
import xgboost as xgb
import numpy as np

from sklearn.metrics import precision_recall_curve 

from setup.create_dataframe import CreateDataframe, load_model
from utils.database import flatten_array_data
from utils.queries import API_ENDPOINTS

logging.basicConfig(stream=sys.stdout, level=logging.WARN, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ domain predicter")

def get_shap_model(bst, data):
    explainer = shap.TreeExplainer(bst)
    shap_values = explainer.shap_values(data)
    explanation = explainer(data)
    return explainer, shap_values, explanation


class DomainPredicter(object):
    """
    Make predictions. Save time
    https://xkcd.com/1690/
    https://xkcd.com/1838/
    https://xkcd.com/552/
    """
    def __init__(self):
        """ Initializes statistical models and SHAP explainers"""
        self.raw_data = None
        self.x_domain = None
        # error margin for "not sure" predictions
        self.error_margin = 0.2
        
        # Load train model
        self.model = xgb.XGBClassifier()
        self.model.load_model("model/xgb_model.json")
        
        # Load model data for setting threshold
        self.model_input_data =  pd.read_pickle("model/df_post_scaling-domains_dataframe.pickle")
        test_idx = pickle.load(open("model/test_idx.pickle", "rb"))
        self.X_test = self.model_input_data.iloc[test_idx,1:].copy()
        self.y_test = self.model_input_data.iloc[test_idx,0].copy()
        self._set_optimal_threshold()
        
    def _crunch_data(self):

        # Create the dataframe
        for endpoint in API_ENDPOINTS:
            flatten_array_data(self.raw_data, endpoint)            
        
        creator = CreateDataframe(self.raw_data, collection="domains_dataframe", load_model=True)
        creator.create_row()
        
        # order columns to how the model trained on them
        cols_when_model_builds = self.model.get_booster().feature_names
        
        # Set the input data
        self.x_domain = creator.df[cols_when_model_builds].iloc[[-1]]
        

    def _set_optimal_threshold(self):
        """ Sets the threshold to optimize f1 score """
        probabilities = self.model.predict_proba(self.X_test)
        
        # keep probabilities for the positive outcome only
        probabilities = probabilities[:, 1]

        precision, recall, thresholds = precision_recall_curve(self.y_test, probabilities)
        f1_scores = 2*recall*precision/(recall+precision)
        self.threshold = thresholds[np.argmax(f1_scores)]
        
    def get_prediction(self, data: dict) -> dict:
        """outputs prediction"""
        if "alerts" in data.keys():
            self.raw_data = data
            self._crunch_data()
        else:
            self.x_domain = pd.DataFrame.from_dict(data)
             
        prob = self.model.predict_proba(self.x_domain)
        positive_prediction = prob[:, 1]
        if positive_prediction > self.threshold:
            verdict = "Malicious"
        elif positive_prediction + self.error_margin > self.threshold:
            verdict = "Not Sure"
        else:
            verdict = "Benign"
        
        # Convert Predictions to log-odds for shap compatability
        evilness = round(np.log(float(positive_prediction) / (1 - float(positive_prediction))), 4)
        evil_threshold = round(np.log(float(self.threshold) / (1 - float(self.threshold))), 4)
        

        _, shap_values, _ = self.get_explanation()
        result = {
            "verdict": verdict,
            "name": self.x_domain.index[0],
            "log_odds": evilness,
            "threshold": evil_threshold,
            "x_domain": self.x_domain.to_dict(),
            "shap_values": shap_values.tolist()
        }
        return result
    
    def get_explanation(self):
        return get_shap_model(self.model, self.x_domain)

