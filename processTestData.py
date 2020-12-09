import os
import numpy as np
import pandas as pd
import sklearn
from sklearn.preprocessing import LabelEncoder

basepath = os.path.dirname(__file__)

def get_test_data(name):
    file_path = os.path.join(basepath,name)
    try:
        dataFrame = pd.read_csv(file_path)
    except:
        raise
        # error = "File does not exist"
        # return error
    else:
        return dataFrame

def get_numpy_array(name):
    file_path = os.path.join(basepath,name)
    
    try:
        numpy_array = np.genfromtxt(file_path, delimiter=',')
    except:
        raise
        # error = "File does not exist"
        # return error
    else:
        return numpy_array