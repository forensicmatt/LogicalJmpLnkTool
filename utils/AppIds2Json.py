import csv
import json


def main():
    tsv_file = open('appids_forensicwiki.tsv', 'r')
    json_file = open('appids_forensicwiki.json', 'w')

    reader = csv.DictReader(tsv_file, delimiter="\t")
    for row in reader:
        json_file.write(json.dumps(row)+"\n")


if __name__ == "__main__":
    main()
