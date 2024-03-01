import "pe"

rule REVERSINGLABS_Cert_Blocklist_093Ff2870Fa33Eaf47259457Ee58C2E0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3fd458e6-bf5a-51f3-9b46-344e9f8e0ffe"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15990-L16006"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1aafe547b8645f07498bac6f0ffd6d5aefbac160aa7a6fb8d1d891e70701ce99"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AEEPZ Limited" and pe.signatures[i].serial=="09:3f:f2:87:0f:a3:3e:af:47:25:94:57:ee:58:c2:e0" and 1503532800<=pe.signatures[i].not_after)
}
