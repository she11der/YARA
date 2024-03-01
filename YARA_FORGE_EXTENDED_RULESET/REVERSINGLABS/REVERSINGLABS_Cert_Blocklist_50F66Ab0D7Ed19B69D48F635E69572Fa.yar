import "pe"

rule REVERSINGLABS_Cert_Blocklist_50F66Ab0D7Ed19B69D48F635E69572Fa : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9938b4c5-4a2b-5f4a-92a0-28c3519b1ed3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15278-L15294"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "28f71c0572e769d4a0cb289071912bc79cddfd98a3a8161c5400c7bee7090bf5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Wei Liu" and pe.signatures[i].serial=="50:f6:6a:b0:d7:ed:19:b6:9d:48:f6:35:e6:95:72:fa" and 1467158400<=pe.signatures[i].not_after)
}
