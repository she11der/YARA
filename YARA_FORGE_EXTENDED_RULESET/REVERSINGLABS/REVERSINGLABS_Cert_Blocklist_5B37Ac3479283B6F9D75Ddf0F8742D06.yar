import "pe"

rule REVERSINGLABS_Cert_Blocklist_5B37Ac3479283B6F9D75Ddf0F8742D06 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "cc124d3f-2446-57a2-a206-0a5e569fc703"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8732-L8748"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b7abd389ac31cd970e6611c7c303714fdd658f45d4857ad524f5e8368edbb875"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ART BOOK PHOTO s.r.o." and pe.signatures[i].serial=="5b:37:ac:34:79:28:3b:6f:9d:75:dd:f0:f8:74:2d:06" and 1619740800<=pe.signatures[i].not_after)
}
