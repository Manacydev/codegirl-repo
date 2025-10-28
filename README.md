# Phishing URL Detector
This project is a web-based application that uses a machine learning model to detect phishing websites. It provides a simple user interface to enter a URL and get a prediction on whether it's a safe or a phishing link.

![image alt](https://github.com/Manacydev/codegirl-repo/blob/main/Screenshot%20(54).png?raw=true)

## Features
Real-time Phishing Detection: Analyzes URLs in real-time to identify potential phishing threats.

User-friendly Interface: A clean and intuitive web interface for easy URL submission.

Probability Score: Provides a confidence score for each prediction, indicating the likelihood of a URL being malicious.

Recent History: Keeps a history of the last 10 scanned URLs for quick reference.

Interactive Game: Includes a fun, interactive game for user engagement.

## How It Works
The application uses a machine learning model trained to classify URLs as either "safe" or "phishing". The process is as follows:

Feature Extraction: When a user submits a URL, the application extracts various features from it. These features include:

URL length and structure

Presence of special characters

Domain information (age, registration length)

HTTPS usage

And many others.

Prediction: The extracted features are then fed into the pre-trained machine learning model.

Result: The model predicts whether the URL is a phishing attempt and returns the result along with a probability score.

## Technologies Used
Backend: Python, Flask

Frontend: HTML, CSS, JavaScript

Machine Learning: Scikit-learn, Pandas, Numpy, Matplotlib, Seaborn

## Model Training
The machine learning model was trained using the Phishing_URL_detection.ipynb notebook. The notebook contains the code for:

Loading and preprocessing the dataset from phishing.csv.

Performing exploratory data analysis (EDA).

Training a classification model.

Evaluating the model's performance.

Saving the trained model and feature names as pickle files.
