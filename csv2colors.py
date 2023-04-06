import sys
import json

from collections import defaultdict as dd
from utils.colors import generate_colors, brightness
import csv

components = dd(list)
colors = {}

with open(sys.argv[1]) as f:
    reader = csv.DictReader(f)
    for row in reader:
        file_hash = row['SHA256']
        file_key = row['Family']
        components[file_key].append(file_hash)

    components = dict(components)
    generated_colors = generate_colors(len(components))
    y = 0
    for file_key in components:
        fill_color = generated_colors[y]
        for file_hash in components[file_key]:
            text_color = (0, 0, 0)
            if brightness(fill_color) < 65:
                text_color = (255, 255, 255)
            colors[file_hash] = (fill_color, text_color)

        y += 1

print(json.dumps(colors))
