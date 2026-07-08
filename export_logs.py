import csv

with open("logs/traffic.log", "r") as infile:
    lines = infile.readlines()

with open("logs/report.csv", "w", newline="") as outfile:

    writer = csv.writer(outfile)

    writer.writerow([
        "Log Entry"
    ])

    for line in lines:
        writer.writerow([line.strip()])

print("CSV Exported Successfully")