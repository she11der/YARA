import "pe"

rule REVERSINGLABS_Cert_Blocklist_D9E834182Dec62C654E775E809Ac1D1B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "30831e91-c2aa-50bc-a0e9-ee7574fc58f4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7220-L7238"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3d8075e34fa3dc221bc2abc2630a93f32efbdde6df270a77b1d6b64d8ce56133"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FoodLehto Oy" and (pe.signatures[i].serial=="00:d9:e8:34:18:2d:ec:62:c6:54:e7:75:e8:09:ac:1d:1b" or pe.signatures[i].serial=="d9:e8:34:18:2d:ec:62:c6:54:e7:75:e8:09:ac:1d:1b") and 1614297600<=pe.signatures[i].not_after)
}
