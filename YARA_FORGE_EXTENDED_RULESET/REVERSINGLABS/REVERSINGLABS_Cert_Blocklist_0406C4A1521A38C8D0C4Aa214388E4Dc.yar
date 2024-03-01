import "pe"

rule REVERSINGLABS_Cert_Blocklist_0406C4A1521A38C8D0C4Aa214388E4Dc : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9019330e-5ab5-5d37-85a1-0e882dbd68ce"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10108-L10124"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f6780751ae553771eb57201a8672847a24512e6279b6a4fd843d8ee2f326860a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Venezia Design SRL" and pe.signatures[i].serial=="04:06:c4:a1:52:1a:38:c8:d0:c4:aa:21:43:88:e4:dc" and 1641859201<=pe.signatures[i].not_after)
}
