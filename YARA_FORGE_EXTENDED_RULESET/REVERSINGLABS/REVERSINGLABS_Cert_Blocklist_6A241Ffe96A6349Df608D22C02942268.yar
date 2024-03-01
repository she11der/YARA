import "pe"

rule REVERSINGLABS_Cert_Blocklist_6A241Ffe96A6349Df608D22C02942268 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8a8decfe-c91a-562c-9376-462cab598373"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11824-L11840"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "79db8be7ca3ed80eb1e3a9401e8fec2b83da8b95b16789ed0b59bb7f4639a94d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HELP, d.o.o." and pe.signatures[i].serial=="6a:24:1f:fe:96:a6:34:9d:f6:08:d2:2c:02:94:22:68" and 1605052800<=pe.signatures[i].not_after)
}
