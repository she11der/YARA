import "pe"

rule REVERSINGLABS_Cert_Blocklist_Cc8D902Da36587C9B2113Cd76C3C3F8D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f9e542aa-eaa5-50a5-95dc-fb55f8575c89"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2750-L2768"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "25e524d23ccc1c06f602a086369ffd44b8c97b76c29f068764081339556b3465"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE4\\xB8\\x8A\\xE6\\xB5\\xB7\\xE9\\x87\\x91\\xE4\\xBF\\x8A\\xE5\\x9D\\xA4\\xE8\\xAE\\xA1\\xE7\\xAE\\x97\\xE6\\x9C\\xBA\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x8D\\xE5\\x8A\\xA1\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (pe.signatures[i].serial=="00:cc:8d:90:2d:a3:65:87:c9:b2:11:3c:d7:6c:3c:3f:8d" or pe.signatures[i].serial=="cc:8d:90:2d:a3:65:87:c9:b2:11:3c:d7:6c:3c:3f:8d") and 1292544000<=pe.signatures[i].not_after)
}
