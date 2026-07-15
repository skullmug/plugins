import omoika
from omoika.elements import TextInput


class ShodanReport(omoika.Plugin):
    version = "1.0.0"
    label = "Shodan Report"
    category = ["Search"]
    color = "#d74e3f"
    icon = "world-question"
    author = "skullmug"
    description = "Represent a Shodan report on an IP address."

    elements = [
        TextInput(label="Region Code", icon="map"),
        TextInput(label="Tags", icon="tag"),
        TextInput(label="Area Code", icon="map-pin"),
        TextInput(label="Domains", icon="link"),
        TextInput(label="Hostnames", icon="server"),
        TextInput(label="Country Code", icon="flag"),
        TextInput(label="Organization", icon="building"),
        TextInput(label="ASN", icon="network"),
        TextInput(label="City", icon="map-pin"),
        TextInput(label="Latitude", icon="navigation"),
        TextInput(label="ISP", icon="wifi"),
        TextInput(label="Longitude", icon="navigation"),
        TextInput(label="Last Update", icon="clock"),
        TextInput(label="Country Name", icon="flag"),
        TextInput(label="Operating System", icon="device-desktop"),
        TextInput(label="Ports", icon="radio"),
    ]
