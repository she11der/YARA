import "pe"

rule REVERSINGLABS_Cert_Blocklist_4D3E38F4Aebbc32257450726B29Be117 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "173f89ca-e7b3-507b-96c1-325dd06210f8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9630-L9646"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f618547942fcd9b3d1104cb5bedeecec8596fa7cc34bca838b6120085b305d73"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "POLE & AERIAL FITNESS LIMITED" and pe.signatures[i].serial=="4d:3e:38:f4:ae:bb:c3:22:57:45:07:26:b2:9b:e1:17" and 1636123882<=pe.signatures[i].not_after)
}
