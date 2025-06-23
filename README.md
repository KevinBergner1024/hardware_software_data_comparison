# CIDDS-113: Comparing real-device hardware data with emulated software data based on [Windows 10 security auditing data](https://learn.microsoft.com/de-de/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/security-auditing-overview). 

The following codebase is part of the paper *Implications of Applying Emulation Data to Machine Learning-Based Intrusion Detection Systems*. 

We finally tested our experiments on [Python 3.9.11](https://www.python.org/downloads/release/python-3911/) with [virtualenv](https://virtualenv.pypa.io/en/latest/user_guide.html) on [Ubuntu 24.04.2 LTS (Noble Numbat) Desktop Version](https://releases.ubuntu.com/noble/). For managing multiple Python versions (e.g., add Python 3.9.11) we used [Pyenv](https://github.com/pyenv/pyenv).

**Example usage commands are included in the following Python scripts:** *wsal_automated_quality_check_script.py*, *wsal_machine_learning_script.py*, *wsal_preprocess_sim_run_into_csv_files.py*, *wsal_wasserstein_distance_event_ids.py*. Use the Python *--help* option to check descriptions.
