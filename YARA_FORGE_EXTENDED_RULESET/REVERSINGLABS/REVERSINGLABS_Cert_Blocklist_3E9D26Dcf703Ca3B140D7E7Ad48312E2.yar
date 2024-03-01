import "pe"

rule REVERSINGLABS_Cert_Blocklist_3E9D26Dcf703Ca3B140D7E7Ad48312E2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3ad650b2-45ea-5324-b8dc-b48094ae2376"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14296-L14312"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d8f70ba61509f3df34705bea0bfcb4cce3e92a33f0f1b65315d886eb5592f152"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dong Qian" and pe.signatures[i].serial=="3e:9d:26:dc:f7:03:ca:3b:14:0d:7e:7a:d4:83:12:e2" and 1440580240<=pe.signatures[i].not_after)
}
