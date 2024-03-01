import "pe"

rule REVERSINGLABS_Cert_Blocklist_1D3F39F481Fe067F8A9289Bb49E05A04 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0c4b6efb-c793-5505-bcd6-f62266c984c6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4290-L4306"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2fdf8b59d302d2ce81a1e9a5715138adc1ec45bd86871c4c2e46412407e329f9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LOGIKA, OOO" and pe.signatures[i].serial=="1d:3f:39:f4:81:fe:06:7f:8a:92:89:bb:49:e0:5a:04" and 1592553220<=pe.signatures[i].not_after)
}
