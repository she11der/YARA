import "pe"

rule REVERSINGLABS_Cert_Blocklist_6Eb02Ac2Beb9611Ed57Eb12E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "64350364-fe74-54df-886d-1197146e00e7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16510-L16526"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7f2a6c61ae82fec6829924d11190da776aebdd3d72c7e001fdc29b215649261c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE6\\x9D\\xA8\\xE5\\x87\\x8C\\xE4\\xBC\\xAF\\xE4\\xB9\\x90\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="6e:b0:2a:c2:be:b9:61:1e:d5:7e:b1:2e" and 1585023767<=pe.signatures[i].not_after)
}
