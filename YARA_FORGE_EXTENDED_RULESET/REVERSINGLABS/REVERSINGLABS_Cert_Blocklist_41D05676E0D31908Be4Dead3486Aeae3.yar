import "pe"

rule REVERSINGLABS_Cert_Blocklist_41D05676E0D31908Be4Dead3486Aeae3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bca4533d-e721-5f23-984a-3b741ca8b53f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4628-L4644"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c4905f02c74df6d05b3f9a6fe2c4f5f32a02bb10da4db929314be043be76d703"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rov SP Z O O" and pe.signatures[i].serial=="41:d0:56:76:e0:d3:19:08:be:4d:ea:d3:48:6a:ea:e3" and 1594857600<=pe.signatures[i].not_after)
}
