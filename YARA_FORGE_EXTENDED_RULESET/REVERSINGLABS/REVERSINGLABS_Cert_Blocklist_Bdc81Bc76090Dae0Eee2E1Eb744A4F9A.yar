import "pe"

rule REVERSINGLABS_Cert_Blocklist_Bdc81Bc76090Dae0Eee2E1Eb744A4F9A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "66feefd2-9cec-56fc-a1c1-11004363462d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5024-L5042"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4fc3e57bedb6fb7c96e6a1ee2ad2aec3860716ac714d52ea58b86be4bbda4660"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALM4U GmbH" and (pe.signatures[i].serial=="00:bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a" or pe.signatures[i].serial=="bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a") and 1579824000<=pe.signatures[i].not_after)
}
