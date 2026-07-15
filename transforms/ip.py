import socket
import httpx
from selenium.webdriver.common.by import By
from omoika import utils
from omoika.errors import PluginError
from omoika.utils import to_camel_case
import httpx
from omoika import transform, Registry



@transform(target="ip@1.0.0", label="To website", icon="world")
async def to_website(self, entity):
    website_entity = await Registry.get_entity('website@1.0.0')
    try:
        resolved = socket.gethostbyaddr(entity.ip_address)
        if len(resolved) >= 1:
            blueprint = website_entity.create(domain=resolved[0])
            return blueprint
        else:
            raise PluginError("No results found")
    except (socket.gaierror, socket.herror):
        raise PluginError("We ran into a socket error. Please try again")


@transform(target="ip@1.0.0", label="To subdomains", icon="world")
async def to_subdomains(self, entity):
    nodes = []
    params = {
        "q": entity.ip_address,
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                'https://api.hackertarget.com/reverseiplookup',
                params=params,
                timeout=None
            )
            data = response.content.decode("utf8").split("\n")
    except Exception as e:
        raise PluginError(e)
    subdomain_entity = await omoika.Registry.get_entity('subdomain')
    for subdomain in data:
        blueprint = subdomain_entity.create(subdomain=subdomain)
        nodes.append(blueprint)
    return nodes


@transform(target="ip@1.0.0", label="To geolocation", icon="map-pin")
async def to_geolocation(self, entity):
    summary_rows = [
        "ASN",
        "Hostname",
        "Range",
        "Company",
        "Hosted domains",
        "Privacy",
        "Anycast",
        "ASN type",
        "Abuse contact",
    ]
    geo_rows = [
        "City",
        "State",
        "Country",
        "Postal",
        "Timezone",
        "Coordinates",
    ]
    if len(entity.ip_address) == 0:
        raise PluginError(
            "A valid IP Address is a required field for this transform"
        )

    geolocation = {}
    summary = {}
    with utils.get_driver() as driver:
        driver.get(f'https://ipinfo.io/{entity.ip_address}')
        for row in summary_rows:
            summary[to_camel_case(row)] = driver.find_element(
                by=By.XPATH, value=self.get_summary_xpath(row)
            ).text
        for row in geo_rows:
            geolocation[to_camel_case(row)] = driver.find_element(
                by=By.XPATH, value=self.get_geo_xpath(row)
            ).text
    IPGeolocationPlugin = await Registry.get_entity('ip_geolocation@1.0.0')
    blueprint = IPGeolocationPlugin.create(
        city=geolocation.get("city"),
        state=geolocation.get("state"),
        country=geolocation.get("country"),
        postal=geolocation.get("postal"),
        timezone=geolocation.get("timezone"),
        coordinates=geolocation.get("coordinates"),
        asn=summary.get("asn"),
        hostname=summary.get("hostname"),
        range=summary.get("range"),
        company=summary.get("company"),
        hosted_domains=summary.get("hostedDomains"),
        privacy=summary.get("privacy"),
        anycast=summary.get("anycast"),
        asn_type=summary.get("asnType"),
        abuse_contact=summary.get("abuseContact"),
    )
    return blueprint


@transform(
    target="ip@1.0.0",
    label="To Shodan",
    icon="world-question",
    deps=["httpx"],
)
async def to_shodan(entity):
    import os
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        raise PluginError(
            "Set the SHODAN_API_KEY environment variable to use this transform."
        )

    ip_address = (entity.ip_address or "").strip()
    if not ip_address:
        raise PluginError("An IP address is required.")

    headers = {"key": api_key, "accept": "application/json"}
    url = f"https://api.shodan.io/shodan/host/{ip_address}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=None)
    except Exception as e:
        raise PluginError(e)

    if response.status_code == 401:
        raise PluginError("Shodan access error.")
    if response.status_code == 404:
        raise PluginError("No results for IP address in Shodan.")
    if response.status_code == 429:
        raise PluginError("Shodan rate limit exceeded. Please try again later.")
    if response.status_code != 200:
        raise PluginError(f"Shodan returned HTTP {response.status_code}.")

    shodan_data = response.json()

    report_entity = await Registry.get_entity("shodan_report@1.0.0")
    blueprint = report_entity.create(
        region_code=shodan_data.get("region_code", ""),
        tags=shodan_data.get("tags", []),
        area_code=shodan_data.get("area_code"),
        domains=shodan_data.get("domains", []),
        hostnames=shodan_data.get("hostnames", []),
        country_code=shodan_data.get("country_code", ""),
        org=shodan_data.get("org", ""),
        asn=shodan_data.get("asn", ""),
        city=shodan_data.get("city", ""),
        latitude=shodan_data.get("latitude"),
        isp=shodan_data.get("isp", ""),
        longitude=shodan_data.get("longitude"),
        last_update=shodan_data.get("last_update", ""),
        country_name=shodan_data.get("country_name", ""),
        os=shodan_data.get("os"),
        ports=shodan_data.get("ports", []),
    )
    return blueprint


def get_summary_xpath(value: str):
    return (
        f"//td//span[contains(text(),'{value}')]"
        "/ancestor::td/following-sibling::td"
    )

def get_geo_xpath(value: str):
    return f"//td[contains(text(),'{value}')]/following-sibling::td"
