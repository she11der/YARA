import "pe"

rule REVERSINGLABS_Cert_Blocklist_0C4324Ff41F0A7B16Ffcc93Dffa8Fa99 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "34594a57-f9fd-5b9d-afb6-691be33da9b5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9438-L9454"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d3ce83fb0497c533a5474d46300c341677ec243686723783798bfbaec4f6e369"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE7\\xA6\\x8F\\xE5\\xBB\\xBA\\xE7\\x9C\\x81\\xE4\\xBA\\x94\\xE6\\x98\\x9F\\xE4\\xBF\\xA1\\xE6\\x81\\xAF\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="0c:43:24:ff:41:f0:a7:b1:6f:fc:c9:3d:ff:a8:fa:99" and 1600300800<=pe.signatures[i].not_after)
}
