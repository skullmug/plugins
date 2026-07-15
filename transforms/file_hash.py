import httpx

from omoika.errors import PluginError
from omoika import transform, Registry


@transform(
    target="file_hash@1.0.0",
    label="To VirusTotal",
    icon="virus-search",
    deps=["httpx"],
)
async def to_virustotal(entity):
    import os
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        raise PluginError(
            "Set the VT_API_KEY environment variable to use this transform."
        )

    file_hash = (entity.hash or "").strip()
    if not file_hash:
        raise PluginError("A file hash (MD5/SHA1/SHA256) is required.")

    headers = {"x-apikey": api_key, "accept": "application/json"}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=None)
    except Exception as e:
        raise PluginError(e)

    if response.status_code == 401:
        raise PluginError("Invalid VirusTotal API key.")
    if response.status_code == 404:
        raise PluginError("Hash not found in VirusTotal.")
    if response.status_code == 429:
        raise PluginError("VirusTotal rate limit exceeded. Please try again later.")
    if response.status_code != 200:
        raise PluginError(f"VirusTotal returned HTTP {response.status_code}.")

    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    threat_label = (
        attributes.get("popular_threat_classification", {})
        .get("suggested_threat_label", "unknown")
    )

    report_entity = await Registry.get_entity("virustotal_report@1.0.0")
    blueprint = report_entity.create(
        detection_ratio=f"{malicious}/{total}",
        threat_label=threat_label,
        file_type=attributes.get("type_description", ""),
        size=str(attributes.get("size", "")),
        sha256=attributes.get("sha256", ""),
        md5=attributes.get("md5", ""),
        reputation=str(attributes.get("reputation", "")),
        times_submitted=str(attributes.get("times_submitted", "")),
        first_seen=str(attributes.get("first_submission_date", "")),
        last_analysis=str(attributes.get("last_analysis_date", "")),
    )
    return blueprint
