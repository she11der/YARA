import "pe"

rule REVERSINGLABS_Cert_Blocklist_2Daa8D629Cc0410A9482E62A0F8Bf8Fc : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "71e627d9-0892-5501-8189-26eae36b7965"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12966-L12982"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cfb2631bc1832f65fb9d77c812bf2a1e05121e825254bd57ae8b21e7b10b2344"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DON'T MISS A WORD LIMITED" and pe.signatures[i].serial=="2d:aa:8d:62:9c:c0:41:0a:94:82:e6:2a:0f:8b:f8:fc" and 1543449600<=pe.signatures[i].not_after)
}
