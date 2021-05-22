#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pandas
import config
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from datetime import datetime
from sklearn.model_selection import train_test_split, cross_val_score, KFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier

def prepare_data(file_csv):
    data = pandas.read_csv(file_csv)
    if "Attack" in data.columns:
        data.drop(['Label'], axis=1, inplace=True)
        data.rename(columns={'Attack':'Label'}, inplace=True)
    if "Total Length of Fwd Packet" in data.columns:
        data.rename(columns={'Total Length of Fwd Packet': 'TotLen Fwd Pkts'}, inplace=True)
        data.rename(columns={'Total Length of Bwd Packet': 'TotLen Bwd Pkts'}, inplace=True)
    if "Fwd Pkts/s" in data.columns:
        data.rename(columns={'Fwd Pkts/s': 'Fwd Packets/s'}, inplace=True)
    if "Pkt Len Min" in data.columns:
        data.rename(columns={'Pkt Len Min': 'Packet Length Min'}, inplace=True)
    try:
        data_clean = data[['Active Max','Flow Duration', 'Fwd IAT Max', 'Fwd IAT Std', 'Fwd Packets/s', 'Packet Length Min', 'Protocol', 'TotLen Bwd Pkts', 'TotLen Fwd Pkts', 'Label']]
    except KeyError as e:
        print(e)
        print(data.columns)
        exit(1)
    del data
    data_clean['Label'] = data_clean['Label'].apply(normalize_label)
    Y = data_clean['Label'].values
    X = data_clean.drop('Label', axis=1).values
    return X,Y

def train(X_train, Y_train):
    # return GaussianProcessClassifier(n_jobs=1).fit(X_train, Y_train)
    return DecisionTreeClassifier(max_depth=5, min_samples_leaf=10, min_samples_split=5).fit(X_train, Y_train)

def classify(model, X, Y):
    Y_result = model.predict(X)
    accuracy = accuracy_score(Y, Y_result)
    precision = precision_score(Y, Y_result)
    recall = recall_score(Y, Y_result)
    f1 = f1_score(Y, Y_result)
    conf_matrix = confusion_matrix(Y, Y_result)
    return accuracy, precision, recall, f1, conf_matrix

def show_correlation(file_csv):
    data = pandas.read_csv(file_csv)
    data['Label'] = data['Label'].apply(normalize_label).astype('category').cat.codes
    #data = data.drop(['Src Port'], axis=1)
    correlation = data.corr(method='pearson')
    columns = correlation.nlargest(15, 'Label').index
    correlation_map = np.corrcoef(data[columns].values.T)
    sns.set(font_scale=0.7)
    heatmap = sns.heatmap(correlation_map, cbar=True, annot=True, square=True, fmt='.2f', yticklabels=columns.values, xticklabels=columns.values)
    plt.show()

def normalize_label(label):
    if label.lower() == "benign":
        return 0
    else:
        return 1

def create_model_and_classify_itself(csv_path, name):
    X,Y = prepare_data(csv_path)
    kfold = KFold(n_splits=5, random_state=21, shuffle=True)
    model = DecisionTreeClassifier(max_depth=5, min_samples_leaf=10, min_samples_split=5)
    cv_results = cross_val_score(model, X, Y, cv=kfold, scoring='f1', n_jobs=4)
    msg = "%s: %f (%f)" % (name, cv_results.mean(), cv_results.std())
    print(msg)
    print("")
    return model.fit(X,Y)

def test(model, csv_path, name_train, name_class):
     X,Y = prepare_data(csv_path)
     print("Processed dataset:", name_class, "at", datetime.now())
     acc, prec, rec, f1, cmatrix = classify(model, X, Y)
     print("## Classified", name_class, "with", name_train,":")
     print("*Accuracy:", acc)
     print("*Precision:", prec)
     print("*Recall:", rec)
     print("*F1:", f1)
     print("*Confussion Matrix:")
     print(cmatrix)
     print(datetime.now())
     print("")

if __name__ == '__main__':
    model = create_model_and_classify_itself(config.dataset_toniot_csv_file, "ToN-IOT")
    test(model, config.dataset_ids2018_csv_file, "ToN-IoT", "ISCX-IDS2018")
    test(model, config.dataset_iot23_csv_file, "ToN-IoT", "IoT23")
    del model
    model = create_model_and_classify_itself(config.dataset_ids2018_csv_file, "ISCX-IDS2018")
    test(model, config.dataset_toniot_csv_file, "ISCX-IDS2018", "ToN-IoT")
    test(model, config.dataset_iot23_csv_file, "ISCX-IDS2018", "IoT23")
    del model
    model = create_model_and_classify_itself(config.dataset_iot23_csv_file, "IoT23")
    test(model, config.dataset_ids2018_csv_file, "IoT23", "ISCX-IDS2018")
    test(model, config.dataset_toniot_csv_file, "IoT23", "ToN-IoT")