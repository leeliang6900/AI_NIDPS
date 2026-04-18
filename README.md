# AI-NIDPS: AI-Based Network Intrusion Detection and Prevention System

---

## 1. Project Overview

This project is an **AI-based Network Intrusion Detection and Prevention System (AI-NIDPS)** designed to monitor network traffic, detect malicious activities, and support real-time threat analysis in a virtualized network environment.

The system combines **machine learning models, rule-based detection, and online learning techniques** to classify network traffic and identify suspicious or malicious behaviour. It also supports automated response actions such as blocking and honeypot redirection, along with a monitoring dashboard for visualization and control.

This project is developed for academic purposes as a Final Year Project (FYP).

---

## 2. Objectives

* To develop an AI-based intrusion detection and prevention system
* To analyze network traffic behaviour using flow-based data
* To detect and classify suspicious and malicious network activities
* To implement automated response mechanisms for detected threats
* To explore online learning for continuous model improvement

---

## 3. System Scope

The system focuses on the following areas:

* Real-time network traffic monitoring using flow-based data
* Feature extraction and data preprocessing
* AI-based classification of network traffic and suspicious behaviour
* Automated response actions such as blocking and honeypot redirection
* Dashboard-based monitoring and system visualization
* Online learning using newly collected traffic samples

The system is deployed and tested in a controlled virtual lab environment.

---

## 4. Dataset

This project uses the **UNSW-NB15 dataset**, a widely used benchmark dataset for network intrusion detection research.

Due to GitHub file size limitations, the dataset is not included in this repository.

### Dataset Sources

* [UNSW Official](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
* [Kaggle Mirror](https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15)

### Dataset Description

* Flow-based network traffic dataset
* Contains normal traffic and multiple attack types
* Approximately 2.5 million records
* 49 input features with class labels

The dataset is described in more detail in `data/README.md`.

---

## 5. System Workflow

The system follows the following workflow:

1. Traffic Collection
2. Data Preprocessing
3. Feature Extraction
4. AI-Based Detection
5. Response Decision
6. Dashboard Monitoring
7. Online Learning and Shadow Model Evaluation

---

## 6. Technologies Used

The system is developed using the following technologies:

* Python (core development language)
* Pandas / NumPy (data processing)
* Scikit-learn / XGBoost (machine learning models)
* River (online learning framework)
* Flask (backend API service)
* React + Vite (frontend dashboard)
* Paramiko (SSH-based router control)
* MikroTik NetFlow v9 (traffic flow export)
* Oracle VirtualBox (virtual lab environment)

These tools are used to simulate a complete network security monitoring and response system.

---

## 7. Project Structure

```text
AI_NIDPS/
│
├── AI_NIDPS_DashBoard/     # Frontend dashboard (React + Vite)
├── data/                   # Dataset and preprocessing files
├── logs/                   # System logs and detection records
├── models/                 # Trained AI models
├── online_learning/        # Online learning data, state, and checkpoints
├── reports/                # Evaluation results and reports
├── security/               # Security utilities and scripts
│
├── arp_resolver.py
├── dashboard_backend.py
├── netflow_v9_receiver.py
├── nidps_monitor.py
├── online_auto_label.py
├── online_control.py
├── online_evaluator.py
├── online_learning_policy.py
├── online_models.py
├── online_store.py
├── online_trainer.py
├── router_ssh.py
├── start_all.py
├── Start_AI_NIDPS.bat
├── train_ai.py
├── train_ai_targeted.py
├── train_malware.py
│
└── README.md
```

---

## 8. Limitations

* The system currently uses a fixed 30-second flow window for detection, which may introduce some delay in real-time scenarios
* Testing has been conducted mainly in a controlled virtual lab environment
* Online learning performance depends on the quality of newly collected samples
* Flow-based analysis has limited visibility compared to full packet inspection

---

## 9. Future Improvements

* Introduce a lightweight early-warning detection mechanism before the full analysis window
* Extend testing to more realistic and diverse network environments
* Improve sample filtering and validation in the online learning pipeline
* Develop a two-stage detection approach combining fast flow-based detection with deeper analysis for suspicious traffic
* Enhance system scalability for larger network deployments

---

## 10. Project Note

Developed as a Final Year Project (FYP) for academic submission.

---

## 11. License

This project is for educational and research purposes only.
