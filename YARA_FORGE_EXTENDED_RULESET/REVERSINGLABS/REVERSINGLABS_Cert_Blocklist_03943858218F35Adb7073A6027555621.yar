import "pe"

rule REVERSINGLABS_Cert_Blocklist_03943858218F35Adb7073A6027555621 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fbaf4c7a-5f20-57f7-b6b7-143fdbf0e5c2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1978-L1994"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "93369d51b73591559494a48fafa5e4f7d46301ecaa379d8de70a70ac4d2d2728"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RuN APps FOrEver lld" and pe.signatures[i].serial=="03:94:38:58:21:8f:35:ad:b7:07:3a:60:27:55:56:21" and 1480550399<=pe.signatures[i].not_after)
}
