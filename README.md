# Project README

## Overview

This project analyzes Internet address survey data collected in two periods: 2013 and 2023. The project includes the following components:

- **Data Files:** Processed data files (CSV and TXT formats) containing various metrics and results.
- **Analysis Code:** Jupyter notebooks that document the exploratory data analysis, data processing, and computation of metrics.
- **Additional Tools:** A custom-built utility (`print_datafile-0.5`) used to convert raw binary survey files into human-readable text format.

## Directory Structure

DSCI599_project/ ├── data/ │ ├── block_metrics_2013.csv │ ├── block_metrics_2023.csv │ ├── classified_block_metrics_2013.csv │ ├── df_2013.csv │ ├── df_2023.csv │ ├── features_2013.csv │ ├── features_2023.csv │ ├── filtered_2013.txt │ ├── filtered_2023.txt │ ├── metrics_2013.csv │ ├── metrics_2023.csv │ ├── output_2013.txt │ ├── output_2023.txt │ └── results.txt ├── notebook/ │ ├── data_exploration.ipynb │ ├── initial_work.ipynb │ └── main_work.ipynb └── print_datafile-0.5/ └── [source code and executable]

## Description of Files

### Data Files (in the `data` folder)

- **output_2013.txt / output_2023.txt:**  
  These files are the direct output from the `print_datafile` utility applied to the raw binary survey files for 2013 and 2023, respectively.

- **filtered_2013.txt / filtered_2023.txt:**  
  These files are created by filtering the respective output files to retain only the records that start with `128`, corresponding to the IP block of focus.

- **df_2013.csv / df_2023.csv:**  
  Processed data files generated by applying the `load_and_process` function on the filtered text files. These files include additional computed columns (such as hop count and formatted timestamp) with a year-specific suffix.

- **metrics_2013.csv / metrics_2023.csv:**  
  Aggregated probe-level metrics computed by grouping the processed data by probe IP addresses. Metrics include availability, volatility, and median up-time.

- **block_metrics_2013_new.csv / block_metrics_2023_new.csv:**  
  These files contain block-level metrics computed via a recursive clustering algorithm. The algorithm starts with /24 blocks and subdivides them (e.g., into /25 blocks or smaller) if the variance in key metrics (availability, volatility, and median up-time) is high. The resulting CSV files capture the aggregated, consistent sub-blocks along with their original /24 block labels.

- **classified_block_metrics_2013.csv (if present):**  
  Contains block-level metrics with additional classification labels (e.g., "always-active", "underutilized") based on a clustering (ML) approach.

- **features_2013.csv / features_2023.csv:**  
  These files include additional intermediate feature extraction results.

### Notebook Files (in the `notebook` folder)

- **data_exploration.ipynb:**  
  This notebook contains exploratory data analysis (EDA) of the survey data. It includes data cleaning, visualization (using matplotlib, seaborn), and initial clustering experiments.

- **initial_work.ipynb:**  
  Contains preliminary analysis work. It loads the processed data (from `df_2013.csv` and `df_2023.csv`), creates time-series plots, and computes basic metrics (availability, volatility, median up-time) on a per-probe basis.

- **main_work.ipynb:**  
  The main analysis notebook where further aggregation is performed. It computes block-level metrics, applies clustering for block classification, and visualizes the results. This notebook includes functions for generating consistent blocks based on IP address groupings and evaluates the ping-observable behavior of each block.

### Additional Tools

- **print_datafile-0.5:**  
  This directory contains the source code and executable for the `print_datafile` utility. This tool was used to convert raw binary output files from the survey into human-readable text files (e.g., converting .bz2 files to .txt files).

## How to Access and Reproduce the Analysis

1. **Data Access:**  
   The processed data files are stored in the `data` folder. Note that the raw binary files were processed using the `print_datafile` utility (instructions for which are in the `print_datafile-0.5` folder).

2. **Code Execution:**  
   - All data and notebooks have been organized within this project directory for clarity.  
     - The **data** folder contains all CSV and TXT files generated during processing.  
     - The **notebook** folder contains all the Jupyter notebooks used for the analysis.
   - Open the notebooks in the `notebook` folder using Jupyter Notebook or JupyterLab.
   - Run the cells sequentially to reproduce the analysis steps from data exploration through block-level classification.
   - The notebooks use the CSV and TXT files in the `data` folder as inputs and output further processed metrics.
   - **Important Note on File Paths:**  
     The file paths in the notebooks have not yet been updated to reflect the new directory structure. If you encounter errors locating data files, please update the paths within the notebooks (for example, changing `df_2013.csv` to `../data/df_2013.csv`) to match the current organization.

3. **Submission Details:**  
   Code, data, and analysis results are provided in this submission. The raw data (or larger files, if applicable) are hosted online at [https://ant.isi.edu/datasets/index.html] (available upon request).

## Final Notes

- **Dependencies:**  
  The analysis was performed using Python 3 with libraries including pandas, numpy, matplotlib, seaborn, scikit-learn, and tqdm. Please ensure these packages are installed to run the notebooks.
