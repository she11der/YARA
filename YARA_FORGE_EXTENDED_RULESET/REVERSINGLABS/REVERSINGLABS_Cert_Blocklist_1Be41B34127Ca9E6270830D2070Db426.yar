import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Be41B34127Ca9E6270830D2070Db426 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bee69e9d-db8e-5d4e-8e97-b3791b4f717d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2468-L2484"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b66c4b9264be70d53838442a3112c4bacbdf2dda90840d71c3eb949e630b3f17"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\x8C\\x97\\xE4\\xBA\\xAC\\xE8\\x80\\x98\\xE5\\x8D\\x87\\xE5\\xA4\\xA9\\xE4\\xB8\\x8B\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="1b:e4:1b:34:12:7c:a9:e6:27:08:30:d2:07:0d:b4:26" and 1352764799<=pe.signatures[i].not_after)
}
