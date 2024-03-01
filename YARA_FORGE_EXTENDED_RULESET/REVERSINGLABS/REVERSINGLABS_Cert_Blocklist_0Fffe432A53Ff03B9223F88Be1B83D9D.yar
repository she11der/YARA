import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Fffe432A53Ff03B9223F88Be1B83D9D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing BabyShark malware."
		author = "ReversingLabs"
		id = "25a4c68b-5774-51a2-9aba-1326c85a5251"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2970-L2986"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e7dbe6b95877f9473661ccf26fa6e5142147609adfe0a9bb8b493875325710af"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "EGIS Co., Ltd." and pe.signatures[i].serial=="0f:ff:e4:32:a5:3f:f0:3b:92:23:f8:8b:e1:b8:3d:9d" and 1498524050<=pe.signatures[i].not_after)
}
