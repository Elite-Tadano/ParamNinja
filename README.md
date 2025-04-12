# ParamNinja
ParamNinja  is a python-based CLI tool designed to mine archived URLs for a given domain. This makes it especially useful for bug bounty hunting, parameter fuzzing, and manual recon. 

## 🐍 <u>How to Install</u> :
Create a virtual environment and install dependencies:

```python
pip install -r requirements.txt
```

## ▶️ <u>How to Use</u> :

```
python param_ninja.py -d example.com
```

You'll be prompted to enter an output filename, such as:
-> Enter the output file name or path to save results (e.g., result.txt): myurls.txt

## 🔧 <u>New Features Implemented</u> :

### 🌍 CommonCrawl Support

- Use -s commoncrawl to fetch URLs from CommonCrawl.

- Or use -s all to get both Wayback + CommonCrawl.

### 🧵 Multi-Domain Support with Threading

- Pass a file to -d domains.txt to scan multiple targets concurrently.

### 📂 Output Directory Support

- Use -o results to specify a folder where all cleaned URLs will be saved (default is results/).

