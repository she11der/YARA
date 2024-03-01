import "pe"

rule REVERSINGLABS_Cert_Blocklist_199A9476Feca3C004Ff889D34545De07 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4bb98380-70e5-5ad9-adb2-2e6e10f35258"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14440-L14456"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "39c6efefcbd78d5e08ffd8d3989cab3bdf273a1847b2a961f9e68c9ee95e85b6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Funcall" and pe.signatures[i].serial=="19:9a:94:76:fe:ca:3c:00:4f:f8:89:d3:45:45:de:07" and 1138060800<=pe.signatures[i].not_after)
}
