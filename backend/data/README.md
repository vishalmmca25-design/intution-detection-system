# Where the data goes

Download the CICIDS2017 CSVs (the "MachineLearningCSV.zip" version with
CICFlowMeter-generated flow features) from the Canadian Institute for
Cybersecurity:

https://www.unb.ca/cic/datasets/ids-2017.html

Unzip and place the 8 daily CSV files here, e.g.:

```
backend/data/
  Monday-WorkingHours.pcap_ISCX.csv
  Tuesday-WorkingHours.pcap_ISCX.csv
  Wednesday-workingHours.pcap_ISCX.csv
  Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
  Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
  Friday-WorkingHours-Morning.pcap_ISCX.csv
  Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
  Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

`train_model.py` automatically loads every `*.csv` in this folder. If this
folder is empty, it falls back to `generate_sample_data.py`, which builds a
small synthetic stand-in dataset so you can see the whole pipeline run
without a ~6GB download. Swap in the real files and rerun training for a
model that's actually trustworthy.
