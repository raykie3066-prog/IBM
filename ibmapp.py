# install
pip install -r requirements.txt

# set keys (or use a .env file)
$env:VT_API_KEY  = "your_vt_key"
$env:OTX_API_KEY = "your_otx_key"

# single lookups
python -m ioc_puller ip 8.8.8.8
python -m ioc_puller domain malware.example.com --format json
python -m ioc_puller hash <sha256> --sources vt --format csv -o out.csv

# batch
python -m ioc_puller batch targets.txt --format json -o results.json
