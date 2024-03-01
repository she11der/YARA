import "pe"

rule REVERSINGLABS_Cert_Blocklist_0D53690631Dd186C56Be9026Eb931Ae2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4f60613c-4162-5b3d-989f-f79a06450f4d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4834-L4850"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3d0a80c062800f935fa3837755e8a91245e01a4e2450a05fecab5564cb62c15c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STA-R TOV" and pe.signatures[i].serial=="0d:53:69:06:31:dd:18:6c:56:be:90:26:eb:93:1a:e2" and 1592190240<=pe.signatures[i].not_after)
}
