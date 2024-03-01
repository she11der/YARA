import "pe"

rule REVERSINGLABS_Cert_Blocklist_7156Ec47Ef01Ab8359Ef4304E5Af1A05 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b285a407-7f71-5c7e-baae-bfa111a50101"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5064-L5080"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7bb093287dd309ce12859eca9a9fc98095b3d52ec860626fe6e743bace262fde"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BOREC, OOO" and pe.signatures[i].serial=="71:56:ec:47:ef:01:ab:83:59:ef:43:04:e5:af:1a:05" and 1597363200<=pe.signatures[i].not_after)
}
