import "pe"

rule REVERSINGLABS_Cert_Blocklist_1A0Fd2A4Ef4C2A36Ab9C5E8F792A35E2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7148a21a-97d6-59a2-a1cf-442c271bc0b5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2654-L2670"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8e768415998a6a92961986cb0a9d310514d928be93b3e5a9aaa9ec71bf5886ad"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\x8C\\x97\\xE4\\xBA\\xAC\\xE9\\x87\\x91\\xE5\\x88\\xA9\\xE5\\xAE\\x8F\\xE6\\x98\\x8C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="1a:0f:d2:a4:ef:4c:2a:36:ab:9c:5e:8f:79:2a:35:e2" and 1389311999<=pe.signatures[i].not_after)
}
