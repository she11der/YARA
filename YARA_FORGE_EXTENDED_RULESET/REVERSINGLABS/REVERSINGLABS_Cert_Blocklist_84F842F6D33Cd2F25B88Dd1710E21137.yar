import "pe"

rule REVERSINGLABS_Cert_Blocklist_84F842F6D33Cd2F25B88Dd1710E21137 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "202593d3-d63a-5852-b680-516504d92031"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3902-L3920"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5aad8e95d1306626b63d767fce4706104330dd776b75c09cc404227863564307"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DataNext s.r.o." and (pe.signatures[i].serial=="00:84:f8:42:f6:d3:3c:d2:f2:5b:88:dd:17:10:e2:11:37" or pe.signatures[i].serial=="84:f8:42:f6:d3:3c:d2:f2:5b:88:dd:17:10:e2:11:37") and 1586775720<=pe.signatures[i].not_after)
}
