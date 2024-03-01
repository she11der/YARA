import "pe"

rule REVERSINGLABS_Cert_Blocklist_09Aecea45Bfd40Ce7D62D7D711916D7D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "421425b1-13ad-5d80-b044-8bd43c60b3ff"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3008-L3024"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d1c6bfb10a244ba866c8aabdff6055388afa8096fd4bd77bb21f781794333e9b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALINA LTD" and pe.signatures[i].serial=="09:ae:ce:a4:5b:fd:40:ce:7d:62:d7:d7:11:91:6d:7d" and 1551052800<=pe.signatures[i].not_after)
}
