import "pe"

rule REVERSINGLABS_Cert_Blocklist_Fe41941464B9992A69B7317418Ae8Eb7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "dd84a6b2-e616-5f93-af50-1a4fc15f3c45"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5444-L5462"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bd5131f2b44deec6a7a68577b80ef4d066c331da2976539ce52ac6cff8d5560e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Milsean Software Limited" and (pe.signatures[i].serial=="00:fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7" or pe.signatures[i].serial=="fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7") and 1599523200<=pe.signatures[i].not_after)
}
