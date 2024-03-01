import "pe"

rule REVERSINGLABS_Cert_Blocklist_127251B32B9A50Bd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing OSX DokSpy backdoor."
		author = "ReversingLabs"
		id = "3581085c-a6e7-571f-8253-f8d9e90e78fc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2158-L2174"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8552ce9e9ab8d6b1025ab3c6e7b2485ef855236114c426475fde0b5f2e231ec9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Developer ID Application: Edouard Roulet (W7J9LRHXTG)" and pe.signatures[i].serial=="12:72:51:b3:2b:9a:50:bd" and 1493769599<=pe.signatures[i].not_after)
}
