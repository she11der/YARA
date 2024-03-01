import "pe"

rule REVERSINGLABS_Cert_Blocklist_328Bdcc0F679C4649147Fbb3Eb0E9Bc6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8e2c2204-8905-5e05-9ec8-e1577ae4c2cb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2770-L2786"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6d9e1f25ca252ca9dda7714c52a2e57fd3b5dca08cd2a45c9dec18a31d3bb342"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Nooly Systems LTD" and pe.signatures[i].serial=="32:8b:dc:c0:f6:79:c4:64:91:47:fb:b3:eb:0e:9b:c6" and 1204847999<=pe.signatures[i].not_after)
}
