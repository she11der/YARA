import "pe"

rule REVERSINGLABS_Cert_Blocklist_9A727E200Ea76570 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d133dac3-3959-50f0-913e-b279ca6a1c2c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12984-L13002"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "337dc486f2bdca1f7682887d5e5c0f82961850a8fd9c9a20b9a43a75334070d8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Alexsandro Da Rosa - ME" and (pe.signatures[i].serial=="00:9a:72:7e:20:0e:a7:65:70" or pe.signatures[i].serial=="9a:72:7e:20:0e:a7:65:70") and 1539056530<=pe.signatures[i].not_after)
}
