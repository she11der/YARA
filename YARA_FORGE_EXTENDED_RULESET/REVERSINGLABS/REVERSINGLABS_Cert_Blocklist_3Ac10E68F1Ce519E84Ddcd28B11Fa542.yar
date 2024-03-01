import "pe"

rule REVERSINGLABS_Cert_Blocklist_3Ac10E68F1Ce519E84Ddcd28B11Fa542 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing Sakula malware."
		author = "ReversingLabs"
		id = "9cc0e518-84c8-5b23-b8cb-e0e0fe7849bd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2104-L2120"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "dac3b6b7609ec1e82afe4f9c6c14e2d32b6f5d8d49c59d6c605f2a94d71bc107"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "U-Tech IT service" and pe.signatures[i].serial=="3a:c1:0e:68:f1:ce:51:9e:84:dd:cd:28:b1:1f:a5:42" and 1420156799<=pe.signatures[i].not_after)
}
