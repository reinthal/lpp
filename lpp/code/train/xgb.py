"""Trains an xgb model and saves to model"""
import pandas as pd
import numpy as np
import argparse, pickle
import logging
import sys
import xgboost as xgb

from sklearn.metrics import precision_recall_curve, confusion_matrix, auc
from sklearn.model_selection import StratifiedShuffleSplit

def save_model(obj, file_path):
    with open(file_path, 'wb') as fp:
        pickle.dump(obj, fp)

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("xgb train")

params = {
        "objective":"binary:logistic",
        "max_depth": 16,
        "gamma": 2.6,
        'alpha': 20,
        'lambda': 1,
        'learning_rate': 0.05,
        'eval_metric':'aucpr',
        "scale_pos_weight": 1,
        "enable_experimental_json_serialization": True,
}


def get_prediction_classes(xgb_model, X_test, y_test):
    lr_probs = xgb_model.predict_proba(X_test)
    
    # keep probabilities for the positive outcome only
    lr_probs = lr_probs[:, 1]

    lr_precision, lr_recall, thresholds = precision_recall_curve(y_test, lr_probs)

    f1_scores = 2*lr_recall*lr_precision/(lr_recall+lr_precision)
    threshold = thresholds[np.argmax(f1_scores)]
    logger.info("Optimal Threshold: {}".format(threshold))
    logger.info("F1 score: {}".format(np.max(f1_scores)))
    
    false_negatives = X_test[(lr_probs < threshold) & (y_test == 1)]
    false_positives = X_test[(lr_probs > threshold) & (y_test == 0)]
    true_positives = X_test[(lr_probs > threshold) & (y_test == 1)]
    true_negatives = X_test[(lr_probs < threshold) & (y_test == 0)]
    return  true_negatives, false_positives, false_negatives, true_positives


def train_model(data, params):
    sss_train_test = StratifiedShuffleSplit(n_splits=1, test_size=0.2)
    sss_train_test.get_n_splits(data.iloc[:,1:], data.iloc[:,0])
    train_idx, test_idx = next(sss_train_test.split(data.iloc[:,1:], data.iloc[:,0]))

    X_train = data.iloc[train_idx,1:].copy()
    y_train = data.iloc[train_idx,0].copy()


    X_test = data.iloc[test_idx,1:].copy()
    y_test = data.iloc[test_idx,0].copy()


    n = sum(y_train+1 % 2)
    p = sum(y_train)
    logger.info("class balance: {}".format(p/n))

    n = sum(y_train+1 % 2)
    p = sum(y_train)
    params["scale_pos_weight"] = n / p

    logger.info("run the xgb algoritm")
    watchlist = [ (X_train, y_train), (X_test, y_test)]

    xgb_model = xgb.XGBClassifier(
        **params,
        num_boost_round=500, 
        early_stopping_rounds=25,
        verbosity=1,
    )
    
    xgb_model.fit(
        X_train, 
        y_train,
        verbose=True,
        eval_set=watchlist,
        eval_metric="aucpr"
    )

    lr_probs = xgb_model.predict_proba(X_test)    
    lr_probs = lr_probs[:, 1]

    y_pred = xgb_model.predict(X_test)
    precision, recall, _ = precision_recall_curve(y_test, y_pred)
    area = auc(recall, precision)
    tn, fp, fn, tp = confusion_matrix(y_test,y_pred).ravel()
    logger.info('------------ Results for XGBClassifier ---------------')
    logger.info(f'cm: TN: {tn} FP: {fp} FN: {fn} TP: {tp}')
    logger.info(f"Area Under P-R Curve: {area}")
    return xgb_model, train_idx, test_idx


def main(collection):
    data = pd.read_pickle("model/df_post_scaling-{}.pickle".format(collection))
    xgb_model, _, test_idx  = train_model(data, params=params)
    save_model(xgb_model, "model/xgb_model.pickle")
    save_model(test_idx, "model/test_idx.pickle")