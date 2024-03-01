import "pe"

rule REVERSINGLABS_Cert_Blocklist_5Fe0Ad6B03C57Ab67A352159004Ca3Db : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d1cf11fc-eb30-54fc-9e34-91ad0c67e694"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13150-L13166"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6f2489421f2effa2089b744f7e137818935fe2339d9216a42686012c51da677b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SpectorSoft Corp." and pe.signatures[i].serial=="5f:e0:ad:6b:03:c5:7a:b6:7a:35:21:59:00:4c:a3:db" and 1402272000<=pe.signatures[i].not_after)
}
