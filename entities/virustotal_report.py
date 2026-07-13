import omoika
from omoika.elements import TextInput


class VirusTotalReport(omoika.Plugin):
    version = "1.0.0"
    label = "VirusTotal Report"
    category = ["Threat Intelligence", "Documents"]
    color = "#39476199"
    icon = "virus-search"
    author = "skullmug"
    description = "Represent a VirusTotal file analysis report."

    elements = [
        TextInput(label="Detection Ratio", icon="chart-pie"),
        TextInput(label="Threat Label", icon="alert-triangle"),
        TextInput(label="File Type", icon="file"),
        TextInput(label="Size", icon="ruler"),
        TextInput(label="SHA256", icon="hash"),
        TextInput(label="MD5", icon="hash"),
        TextInput(label="Reputation", icon="thumb-up"),
        TextInput(label="Times Submitted", icon="upload"),
        TextInput(label="First Seen", icon="calendar"),
        TextInput(label="Last Analysis", icon="clock"),
    ]
