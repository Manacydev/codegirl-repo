# Phishing URL Detector
This project is a web-based application that uses a machine learning model to detect phishing websites. It provides a simple user interface to enter a URL and get a prediction on whether it's a safe or a phishing link.

![image alt](https://github.com/Manacydev/codegirl-repo/blob/main/Screenshot%20(54).png?raw=true)
![image alt](https://github.com/Manacydev/codegirl-repo/blob/706319e19bf2ff90a2851a1e1ccf557aa4c34ab7/Screenshot%20(53).png)

If you enter a safe website, it will give the result as it is safe and also will mention how much it is safe whereas incase of any phishing website, it will get you a percentage which is below 85% and give you the result it is not safe to use.

![image alt](https://github.com/Manacydev/codegirl-repo/blob/9dd816910cd10e8b68bb7f7f5c6b8f8f214d47c3/Screenshot%20(56).png)

## Features
**Real-time Phishing Detection:** Analyzes URLs in real-time to identify potential phishing threats.

**User-friendly Interface:** A clean and intuitive web interface for easy URL submission.

**Probability Score:** Provides a confidence score for each prediction, indicating the likelihood of a URL being malicious.

**Recent History:** Keeps a history of the last 10 scanned URLs for quick reference.

**Interactive Game:** Includes a fun, interactive game for user engagement.

## How It Works
The application uses a machine learning model trained to classify URLs as either "safe" or "phishing". The process is as follows:

**Feature Extraction:** When a user submits a URL, the application extracts various features from it. These features include:

URL length and structure

Presence of special characters

Domain information (age, registration length)

HTTPS usage

And many others.

**Prediction:** The extracted features are then fed into the pre-trained machine learning model.

**Result:** The model predicts whether the URL is a phishing attempt and returns the result along with a probability score.

## Technologies Used
**Backend:** Python, Flask

**Frontend:** HTML, CSS, JavaScript

**Machine Learning:** Scikit-learn, Pandas, Numpy, Matplotlib, Seaborn

## App Structure

 ```
codegirl-repo/
│
├── app.py                  # Main Flask application logic
|        
│
├── model/
│   ├── Phishing_URL_detection.pkl  # The trained machine learning model
│   └── feature_names.pkl           # The list of feature names used by the model
│
|
├──Phishing_URL_detection.ipynb # Jupyter Notebook for model training and exploration
│
|
└── templates/
    └── index.html          # HTML file for the user interface, also contains CSS and JS
 ```

## Model Training
The machine learning model was trained using the Phishing_URL_detection.ipynb notebook. The notebook contains the code for:

Loading and preprocessing the dataset from phishing.csv.

Performing exploratory data analysis (EDA).

Training a classification model.

Evaluating the model's performance.

Saving the trained model and feature names as pickle files.
