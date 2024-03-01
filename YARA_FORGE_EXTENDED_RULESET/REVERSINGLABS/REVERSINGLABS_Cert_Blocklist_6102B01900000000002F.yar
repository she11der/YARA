import "pe"

rule REVERSINGLABS_Cert_Blocklist_6102B01900000000002F : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "b98769c6-805e-5cd0-96f1-67418fec40a6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1091-L1106"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6c42daa8b8730541bb422ac860ec4b0830e00fdb732e4bb503054dbcae1ff6d4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Microsoft Enforced Licensing Registration Authority CA (SHA1)" and pe.signatures[i].serial=="61:02:b0:19:00:00:00:00:00:2f")
}
