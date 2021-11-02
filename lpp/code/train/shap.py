import pickle
import shap
import argparse
import xgboost as xgb
import pandas as pd

def get_shap_model(bst, data):
    explainer = shap.TreeExplainer(bst)
    shap_values = explainer.shap_values(data)
    explanation = explainer(data)
    return explainer, shap_values, explanation

def main():
    parser = argparse.ArgumentParser(description='export shap model to model/')
    parser.add_argument("-d", "--data", required=True)
    parser.add_argument("-m", "--model", required=True)
    args = parser.parse_args()
    model = xgb.XGBClassifier()
    model.load_model(args.model)
    data = pd.read_pickle(args.data)
    explainer, shap_values, explanation = get_shap_model(model, data)
    with open("model/shap_explainer-{}.pickle", "wb") as fp:
        pickle.dump(explainer, fp)
    with open("model/shap_values-{}.pickle", "wb") as fp:
        pickle.dump(shap_values, fp)
    with open("model/shap_explaination-{}.pickle", "wb") as fp:
        pickle.dump(explanation, fp)

if __name__ == "__main__":
    main()