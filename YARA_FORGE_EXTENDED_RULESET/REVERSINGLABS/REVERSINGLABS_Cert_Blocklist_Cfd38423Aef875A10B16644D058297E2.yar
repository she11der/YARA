import "pe"

rule REVERSINGLABS_Cert_Blocklist_Cfd38423Aef875A10B16644D058297E2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f53e4f44-dde2-5f7a-8cab-71e91ff75d28"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9708-L9726"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a2f67cbf31c9db2891892c31a7ed4ce7eccd834bfb10ae70f58e46f8e68e7c17"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TRUST DANMARK ApS" and (pe.signatures[i].serial=="00:cf:d3:84:23:ae:f8:75:a1:0b:16:64:4d:05:82:97:e2" or pe.signatures[i].serial=="cf:d3:84:23:ae:f8:75:a1:0b:16:64:4d:05:82:97:e2") and 1632884040<=pe.signatures[i].not_after)
}
