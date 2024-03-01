import "pe"

rule REVERSINGLABS_Cert_Blocklist_621E696C3A6371E77A678Cbf0Ee34Ab2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "606749dc-f4ef-526a-8583-486401866759"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15224-L15240"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "67c9fd92681d6dd1172509113e167e74e07f1f86fd62456758b3e3930180b528"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="62:1e:69:6c:3a:63:71:e7:7a:67:8c:bf:0e:e3:4a:b2" and 1467072000<=pe.signatures[i].not_after)
}
