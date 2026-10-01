import pandas as pd
df = pd.read_csv('data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv', nrows=1, encoding='latin-1')
cols = [c.strip() for c in df.columns]
for idx, col in enumerate(cols):
    print(f"{idx}: {repr(col)}")
