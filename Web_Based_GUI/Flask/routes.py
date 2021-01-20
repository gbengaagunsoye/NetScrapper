import os
import sys
from time import time
from flask import render_template, flash, session, request, redirect, url_for
from werkzeug.utils import secure_filename
from app import app
from joblib import load
from app import capture

from app import processTestData
# from keras.models import load_model
# model = load_model('model.h5')
from numpy import genfromtxt
from sklearn.metrics import classification_report
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix

basepath = os.path.dirname(__file__)

try:
    import tensorflow
except:
    error = "Not working"
    print(error)

def kNearestNeighbor():
    return load("app/KNN_traffic_classification.joblib")
 
def randomForest():
    return load("app/RF_traffic_classification.joblib")
 
def artificialNeuralNetwork():
    try:
        model = load_model('app/ANN_model2.h5')
        return model
    except:
        msg = "ANN Model could not be loaded"
        return msg
 
switcher = {
        'KNN': kNearestNeighbor, #KNN
        'RF':  randomForest, #RF
        'ANN': artificialNeuralNetwork #ANN
    }

# from capture import sniffNIC
def loadModel(model_name):
    func = switcher.get(model_name, "nothing")
    # Execute the function
    return func() 

def requestResults(model_name, name):
    try:
        pipeline = loadModel(model_name)
        #To handle RF and KNN Classifiers separately
        if str(model_name) != 'ANN':
            flows = processTestData.get_test_data(name)
            X_test = flows[flows.columns[:-1]]
            y_test = flows[flows.columns[-1]]
            flows['prediction'] = pipeline.predict(X_test)
            data = str(flows.prediction.value_counts()) + '\n\n'
            report = classification_report(y_test, flows['prediction'])
            for x in report:
                x = "<br>{}<br>".format(x)
            score = pipeline.score(X_test, y_test)
            matrix = confusion_matrix(y_test, flows['prediction'])
            result = {"predictions":data, "output": flows, "report":report, "score":score, "matrix":matrix}
            # return report + "<div>" + matrix + "<\div>"
            return result
        else:
            pipeline.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
            X_test = processTestData.get_numpy_array(name)
            loss, accuracy = pipeline.evaluate(X_test, y_test, verbose=2)
            predictions = pipeline.predict_classes(X_test)
            # classes = np.argmax(predictions, axis = 1)
            classes = encoder.inverse_transform(predictions)
            return classes

    except:
        error_msg = "Test Data does not match with this {} model design ".format(model_name)
        return error_msg
    


@app.route('/')
@app.route('/index')
def index():
    # session.clear()
    # return render_template('index.html', title='Home')
    return render_template('index_edited.html', title='Home')


# when the post method detect, then redirect to success function
@app.route('/', methods=['POST', 'GET'])
def get_data():
    if request.method == 'POST':
        net_interface = request.form['search']
        packet_count = 10
        # net_parameter = {'interface': request.form['search'], 'packet_count': 10}
        pcap_file = os.path.join(basepath, net_interface)
        if os.path.isfile(pcap_file):
            # pcap_file = str(pcap_file)
            # return redirect(url_for('trace', packet_src=pcap_file))
            return redirect(url_for('trace', packet_src=net_interface))    
        else:
            return redirect(url_for('data_capture', packet_src=net_interface, packet_count=packet_count))

#Processes uploaded test data and return predictions
@app.route('/success/<model_name>/<name>')
def success(model_name, name):
    # return "<xmp>" + str(requestResults(model_name, name)) + " </xmp> "
    # result = str(requestResults(model_name, name))
    result = requestResults(model_name, name)
    title = str(model_name) + " Predictions"
    # return render_template('predictions.html', title=title, result=result)
    return render_template('prediction2.html', title=title, result=result)
    # return "<table>" + str(requestResults(model_name, name)) + "</table>"

@app.route('/trace/<packet_src>')
def trace(packet_src):
    pcap_file = packet_src
    # pcap_file = '/home/gbenga/AppProbe/app/GTBank_Capture.pcapng'
    summary = capture.process_pcap_file(pcap_file)
    trace_output = {'packet_src': packet_src, 'output': summary }
    return render_template('home.html', title='Home', trace_output=trace_output)


@app.route('/home/<name>')
def home(name):
    user = {'username': name}
    return render_template('home.html', title='Home', user=user)

@app.route('/data_capture/<packet_src>/<packet_count>', methods=['POST', 'GET'])
def data_capture(packet_src, packet_count):
    summary = capture.sniffPacket(packet_src, packet_count)
    trace_output = {'packet_src': packet_src, 'output': summary }
    return render_template('home.html', title='Home', trace_output=trace_output)

############################################################
#                   KNN ROUTES
############################################################

@app.route('/knn/upload_data', methods=['GET', 'POST'])
def upload_data(model_name='KNN'):
    # session.clear()
    # Validation images extension
    image_type_ok = ['csv']
    model_name = model_name
    title = model_name

    if request.method == 'POST':
        if 'data_file' not in request.files:
            response = {
                'message': "No file uploaded within the POST body."
            }
            return response, 400

        f = request.files['data_file']
        source_file = f.filename

        # Save the file to ./uploads
        file_path = os.path.join(
            basepath, 'Uploads', secure_filename(f.filename))
        f.save(file_path)
        flash('Your file {}, has been successfully uploaded'.format(file_path))
        # session['image_path'] = file_path

        # image_type = imghdr.what(file_path)

        # if image_type in image_type_ok_list:
        #     result, saved_file_path, inf_time = run_detect(file_path)
        #     result_img = rename_file(file_path, saved_file_path)
        #     session['inf_time'] = inf_time

        return redirect(url_for('success', model_name=model_name, name=source_file))
    return render_template('data_upload.html', title=model_name, model_name=model_name)

############################################################
#                   RandomForest ROUTES
############################################################
@app.route('/rf/upload_data', methods=['GET', 'POST'])
def rf_upload_data(model_name='RF'):
    model_name = model_name
    if request.method == 'POST':
        if 'data_file' not in request.files:
            response = {
                'message': "No file uploaded within the POST body."
            }
            return response, 400

        f = request.files['data_file']
        source_file = f.filename

        # Save the file to ./uploads
        file_path = os.path.join(
            basepath, 'Uploads', secure_filename(f.filename))
        f.save(file_path)
        flash('Your file {}, has been successfully uploaded'.format(file_path))

        return redirect(url_for('success', model_name=model_name, name=source_file))
    return render_template('data_upload.html', title=model_name, model_name=model_name)


############################################################
#                   ANN ROUTES
############################################################


@app.route('/ann/upload_data', methods=['GET', 'POST'])
def ann_upload_data(model_name='ANN'):
    model_name = model_name
    if request.method == 'POST':
        if 'data_file' not in request.files:
            response = {
                'message': "No file uploaded within the POST body."
            }
            return response, 400

        f = request.files['data_file']
        source_file = f.filename

        # Save the file to ./uploads
        file_path = os.path.join(
            basepath, 'Uploads', secure_filename(f.filename))
        f.save(file_path)
        flash('Your file {}, has been successfully uploaded'.format(file_path))

        return redirect(url_for('success', model_name=model_name, name=source_file))
    return render_template('data_upload.html', title=model_name, model_name=model_name)
