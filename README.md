# phishing-detection-machine-learning-wazuh-scripts

## About this project

## Contributors
- [@Spades0](https://github.com/Spades0) co-author.
- [@xrisbarney](https://github.com/xrisbarney) co-author.
- [@kahlflekzy](https://github.com/kahlflekzy) assisted with building the machine learning model and optimizing the URL extraction script.

## Resources used
- [shreyagopal](https://github.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/blob/master/URL%20Feature%20Extraction.ipynb): We built on their URL features extraction script to create our own features extraction script.
- [olafhartong](https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml): To capture victim endpoint logs.

## Tools used
- [Wazuh](https://github.com/wazuh/wazuh): An open source SIEM and XDR. This was used for detecting when a URL is opened, and its integration script subsequently determined if the URL was phishing or not.
- [Google Colab](https://colab.research.google.com/): Used for generating and training the model.
- [Phishtank](https://phishtank.org/): The phishing blacklist API used.
- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon): For advanced logging.

## Todo
- Fine tune Sysmon config to pick all URLs opened regardless of browser used, mode of opening e.t.c
- Upload Wazuh detection rules.
- Add Wazuh integration directions.
- Add a proper description about the project.

