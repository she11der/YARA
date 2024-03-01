import "pe"

rule REVERSINGLABS_Cert_Blocklist_1A3Faaeb3A8B93B2394Fec36345996E6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "343e4dbe-21a6-5758-be81-e5e7918c54fa"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L657-L673"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a3bd9aaba8dbdb340b5d3013684584524eb08b11339985ba6ca0291b8c8bc692"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "salvatore macchiarella" and pe.signatures[i].serial=="1a:3f:aa:eb:3a:8b:93:b2:39:4f:ec:36:34:59:96:e6" and 1468454400<=pe.signatures[i].not_after)
}
