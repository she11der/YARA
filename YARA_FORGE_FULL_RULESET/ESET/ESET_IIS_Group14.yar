import "pe"

rule ESET_IIS_Group14
{
	meta:
		description = "Detects Group 14 native IIS malware family"
		author = "ESET Research"
		id = "c773b09e-9f24-5e75-ba80-4be69af70b06"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/badiis/badiis.yar#L525-L552"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "ef10a4dfb1a9164533677416a7c9ada715ce10bfc1e5f92b56cf54bd890d4575"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$i1 = "agent-self: %s"
		$i2 = "/utf.php?key="
		$i3 = "/self.php?v="
		$i4 = "<script type=\"text/javascript\" src=\"//speed.wlaspsd.co"
		$i5 = "now.asmkpo.co"
		$s1 = "Baiduspider"
		$s2 = "360Spider"
		$s3 = "Sogou"
		$s4 = "YisouSpider"
		$s6 = "HTTP_X_FORWARDED_FOR"

	condition:
		ESET_IIS_Native_Module_PRIVATE and 2 of ($i*) or 5 of them
}
