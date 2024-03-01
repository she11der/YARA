import "pe"

rule REVERSINGLABS_Cert_Blocklist_03866Deb183Abfbf4Ff458D4De7Bd73A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2641eb86-94f0-537c-a82a-6a5e1596ee84"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2450-L2466"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "90d09d0d2d01500e0670277d0e8de574feecf7443cf4d077912b1166a9c14c43"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE9\\x87\\x8D\\xE5\\xBA\\x86\\xE8\\xAF\\x9D\\xE8\\xAF\\xAD\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="03:86:6d:eb:18:3a:bf:bf:4f:f4:58:d4:de:7b:d7:3a" and 1371772799<=pe.signatures[i].not_after)
}
