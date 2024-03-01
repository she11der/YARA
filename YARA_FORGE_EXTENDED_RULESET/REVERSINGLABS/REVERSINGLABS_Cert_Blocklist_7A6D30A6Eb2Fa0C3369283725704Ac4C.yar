import "pe"

rule REVERSINGLABS_Cert_Blocklist_7A6D30A6Eb2Fa0C3369283725704Ac4C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b7830a3a-ddcc-54ef-84dd-5d4b13863f90"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9094-L9110"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "788abb53ed7974d87c1b1bdbe31dcd3e852ea64745d94780d78d1217ee0206fe"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Trade By International ApS" and pe.signatures[i].serial=="7a:6d:30:a6:eb:2f:a0:c3:36:92:83:72:57:04:ac:4c" and 1619568000<=pe.signatures[i].not_after)
}
