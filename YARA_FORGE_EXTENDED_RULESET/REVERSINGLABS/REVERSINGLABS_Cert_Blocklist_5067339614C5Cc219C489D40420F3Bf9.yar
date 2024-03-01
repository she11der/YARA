import "pe"

rule REVERSINGLABS_Cert_Blocklist_5067339614C5Cc219C489D40420F3Bf9 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "6e0cb6f9-0a92-5eb2-b13f-f9c4eb0ae6b1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1834-L1850"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1716087285a093a3467583f79d7ae9bee641997227e6d4f95047905aedcc97c6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "D-LINK CORPORATION" and pe.signatures[i].serial=="50:67:33:96:14:c5:cc:21:9c:48:9d:40:42:0f:3b:f9" and 1441238400<=pe.signatures[i].not_after)
}
