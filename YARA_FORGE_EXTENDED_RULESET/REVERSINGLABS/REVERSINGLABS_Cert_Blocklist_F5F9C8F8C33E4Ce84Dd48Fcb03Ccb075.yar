import "pe"

rule REVERSINGLABS_Cert_Blocklist_F5F9C8F8C33E4Ce84Dd48Fcb03Ccb075 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "74203aa1-e5d0-59d9-b9f8-b79f5fbe271e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12590-L12608"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ac3bab3f5a93099f39b0862b419346d1eb3d0f75d86e121ba30626d496c46c57"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Abdulkadir \\xC5\\x9Eahin" and (pe.signatures[i].serial=="00:f5:f9:c8:f8:c3:3e:4c:e8:4d:d4:8f:cb:03:cc:b0:75" or pe.signatures[i].serial=="f5:f9:c8:f8:c3:3e:4c:e8:4d:d4:8f:cb:03:cc:b0:75") and 1545004800<=pe.signatures[i].not_after)
}
