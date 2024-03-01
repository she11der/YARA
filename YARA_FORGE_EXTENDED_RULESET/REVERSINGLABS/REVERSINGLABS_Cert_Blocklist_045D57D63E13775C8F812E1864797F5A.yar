import "pe"

rule REVERSINGLABS_Cert_Blocklist_045D57D63E13775C8F812E1864797F5A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c2c37ddc-51bc-58da-b770-df97aebca01d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13602-L13618"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d3e61e9a43f5b17ebb08b71dc39648d1f20273a18214f39605f365f9f0f72c10"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yuanyuan Mei" and pe.signatures[i].serial=="04:5d:57:d6:3e:13:77:5c:8f:81:2e:18:64:79:7f:5a" and 1485043200<=pe.signatures[i].not_after)
}
