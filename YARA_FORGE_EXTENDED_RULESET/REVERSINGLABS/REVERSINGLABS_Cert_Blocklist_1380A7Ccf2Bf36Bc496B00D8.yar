import "pe"

rule REVERSINGLABS_Cert_Blocklist_1380A7Ccf2Bf36Bc496B00D8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "dc473451-e1a9-53b4-acf6-9ff8036ecf31"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16474-L16490"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "88708d7d139a9d6e92f78df460b527a1ae6a404d0bcccb801c8c8cb1263a46c6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="13:80:a7:cc:f2:bf:36:bc:49:6b:00:d8" and 1478069976<=pe.signatures[i].not_after)
}
