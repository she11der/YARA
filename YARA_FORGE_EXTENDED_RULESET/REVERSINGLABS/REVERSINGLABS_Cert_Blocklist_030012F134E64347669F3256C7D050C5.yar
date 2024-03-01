import "pe"

rule REVERSINGLABS_Cert_Blocklist_030012F134E64347669F3256C7D050C5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1e61a781-d5fb-5f05-81c4-3cc697ece13c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6790-L6806"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1a55856bfa4c632b2b0404686dc7ba5e7238b619dd4d2eb68c3d291bc86e52c4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Futumarket LLC" and pe.signatures[i].serial=="03:00:12:f1:34:e6:43:47:66:9f:32:56:c7:d0:50:c5" and 1604036657<=pe.signatures[i].not_after)
}
