import "pe"

rule REVERSINGLABS_Cert_Blocklist_4631713E66E91347F0388B98Cf747794 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6c541522-98ab-5acb-af84-c005c9721e1f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12462-L12478"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cb517cda67150b7e17ee3bd946903e8e8eca81742a362032249a2f2387e71c50"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\xB9\\xBF\\xE5\\xB7\\x9E\\xE6\\x98\\x8A\\xE5\\x8A\\xA8\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="46:31:71:3e:66:e9:13:47:f0:38:8b:98:cf:74:77:94" and 1488240000<=pe.signatures[i].not_after)
}
