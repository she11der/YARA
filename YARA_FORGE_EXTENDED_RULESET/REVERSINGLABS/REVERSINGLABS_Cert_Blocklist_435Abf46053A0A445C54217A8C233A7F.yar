import "pe"

rule REVERSINGLABS_Cert_Blocklist_435Abf46053A0A445C54217A8C233A7F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "538d7405-be17-519e-beb5-fbef3beaedd3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11974-L11990"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "839f55e8fe7a86aad406e657fdef48925543b5d3884927104fd3786444a8fccc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Kodemika" and pe.signatures[i].serial=="43:5a:bf:46:05:3a:0a:44:5c:54:21:7a:8c:23:3a:7f" and 1616976000<=pe.signatures[i].not_after)
}
