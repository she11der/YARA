import "pe"

rule REVERSINGLABS_Cert_Blocklist_1362E56D34Dc7B501E17Fa1Ac3C3E3D9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9dccd009-eca1-5f21-b5ef-1a75f9d93c7d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3580-L3596"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0415c5a49076bab23dfc29ef2d6168b93d6bfde07a89ccb0368d2c967422407a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO  \"Amaranth\"" and pe.signatures[i].serial=="13:62:e5:6d:34:dc:7b:50:1e:17:fa:1a:c3:c3:e3:d9" and 1575936000<=pe.signatures[i].not_after)
}
