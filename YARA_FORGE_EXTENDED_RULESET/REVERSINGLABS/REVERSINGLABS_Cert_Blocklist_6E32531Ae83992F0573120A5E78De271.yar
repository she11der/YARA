import "pe"

rule REVERSINGLABS_Cert_Blocklist_6E32531Ae83992F0573120A5E78De271 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "37fc58ea-63d4-569d-968f-f4775403b0bb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1852-L1868"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2b6d54ea8395c3666906b2e60c30b970c2c1b6f55ded874cbcc22dc79391fb34"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "3 AM CHP" and pe.signatures[i].serial=="6e:32:53:1a:e8:39:92:f0:57:31:20:a5:e7:8d:e2:71" and 1451606399<=pe.signatures[i].not_after)
}
