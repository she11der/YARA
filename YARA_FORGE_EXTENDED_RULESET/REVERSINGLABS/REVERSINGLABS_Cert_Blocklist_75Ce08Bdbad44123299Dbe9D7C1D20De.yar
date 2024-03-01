import "pe"

rule REVERSINGLABS_Cert_Blocklist_75Ce08Bdbad44123299Dbe9D7C1D20De : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e8e2d3b6-077f-56ba-9f2a-1941bf2ebdeb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9748-L9764"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8ba66ab55f9a6755e11a7f39152aa26917271c7f6bc5ffdb42d07ad791fb47d7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rose Holm International ApS" and pe.signatures[i].serial=="75:ce:08:bd:ba:d4:41:23:29:9d:be:9d:7c:1d:20:de" and 1631007095<=pe.signatures[i].not_after)
}
