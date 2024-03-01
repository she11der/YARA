import "pe"

rule REVERSINGLABS_Cert_Blocklist_214Df59Fe53874Cc011Dd45727035F51 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9265bb94-b183-523f-91bf-9bc76ab63d6b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16044-L16060"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "96269f41f82621aee029f343acfce70c781bf7713588dfe78fac35a3d1d3f7cd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="21:4d:f5:9f:e5:38:74:cc:01:1d:d4:57:27:03:5f:51" and 1468800000<=pe.signatures[i].not_after)
}
