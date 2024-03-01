import "pe"

rule REVERSINGLABS_Cert_Blocklist_6724340Ddbc7252F7Fb714B812A5C04D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2b61de88-9fea-5c3f-a7ab-db91e90b4965"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L711-L727"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bc72c2ca5f81198684233e23260831da5b9ef4e7ac5a25abbdb303eecc38bd53"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "YNK JAPAN Inc" and pe.signatures[i].serial=="67:24:34:0d:db:c7:25:2f:7f:b7:14:b8:12:a5:c0:4d" and 1306195199<=pe.signatures[i].not_after)
}
