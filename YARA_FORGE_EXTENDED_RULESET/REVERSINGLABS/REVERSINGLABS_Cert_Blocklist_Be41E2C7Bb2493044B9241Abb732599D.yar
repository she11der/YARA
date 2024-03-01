import "pe"

rule REVERSINGLABS_Cert_Blocklist_Be41E2C7Bb2493044B9241Abb732599D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "81e5a8f3-0893-534a-ab4f-5c2c47078b40"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4178-L4196"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "eb5d94b80fd030d14dc26878895c61761825f3c77209ca0280e88dcd1800f9c2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Company Babylon" and (pe.signatures[i].serial=="00:be:41:e2:c7:bb:24:93:04:4b:92:41:ab:b7:32:59:9d" or pe.signatures[i].serial=="be:41:e2:c7:bb:24:93:04:4b:92:41:ab:b7:32:59:9d") and 1589146251<=pe.signatures[i].not_after)
}
