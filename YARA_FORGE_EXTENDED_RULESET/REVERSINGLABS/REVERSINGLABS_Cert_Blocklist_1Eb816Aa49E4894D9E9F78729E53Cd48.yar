import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Eb816Aa49E4894D9E9F78729E53Cd48 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d2e66765-bdf6-59ff-ac6c-1a82ecefa731"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16782-L16798"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4e22568612aec050c7f78b81ba6749528a9c25c0ba43e14260a581a9bea7a2f0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\x96\\x84\\xE5\\x90\\x9B \\xE9\\x9F\\xA6" and pe.signatures[i].serial=="1e:b8:16:aa:49:e4:89:4d:9e:9f:78:72:9e:53:cd:48" and 1429056000<=pe.signatures[i].not_after)
}
