# README
# ELEC0138 Security and Privacy Final Project (Intrusion Detection Model)
This repository aims at implementing a deep LSTM-based intrusion detection model, using [UNSW-NB15](https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15/data') as training data.

## 💎 Code Structure
Before data cleaning or model training, you can download data mentioned above and put them under [`Detect_Data`](./Detect_Data/)
* [`Data_cleaning.ipynb`](./Data_cleaning.ipynb): we perform data cleaning and analysis here, the result is saved as [`cleaned.csv`]
* [`Model.py`](./Model.py): define model architecture
* [`Model_training.ipynb`](./Model_training.ipynb): use this jupyter notebook to train the model
* [`DetectAttack.py`](./DetectAttack.py): define function that can predict threats with network packets using trained model
* [`capture.py`](./capture.py): Utilise `scapy` to sniff relevant packets.

* [`Detect_Data`](./Detect_Data/): data used for training (Note: data does not exsit because GitHub file should be smaller than 25 MB)
    * [`cleaned.csv`]: cleaned data
    * [`NUSW-NB_features.csv`]: features of pkts
    * [`UNSW-NB15_1.csv`]: original data 1
    * [`UNSW-NB15_2.csv`]: original data 2
    * [`UNSW-NB15_3.csv`]: original data 3
    * [`UNSW-NB15_4.csv`]: original data 4

* [`result`](./result/): our trained model is saved here
    * [`detectThreat.h5`](./result/detectThreat.h5): Intrusion detection model

## 💎 Installation and Requirements
The code requires common Python environments for model training:
- Python 3.11.5
- tensorflow==2.x
- numpy==1.26.1
- pandas==2.1.1
- scapy==2.5.0