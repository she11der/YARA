import "pe"

rule REVERSINGLABS_Cert_Blocklist_013472D7D665557Bfa0Dc21B350A361B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9b63f06d-9808-5936-aad2-d387c74eccdd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15022-L15038"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ab908ef0fca56753bcba8bc85e2fdf5859b4e226c179ec5c6eb6eb3dc4014a8e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yongli Zhang" and pe.signatures[i].serial=="01:34:72:d7:d6:65:55:7b:fa:0d:c2:1b:35:0a:36:1b" and 1470960000<=pe.signatures[i].not_after)
}
