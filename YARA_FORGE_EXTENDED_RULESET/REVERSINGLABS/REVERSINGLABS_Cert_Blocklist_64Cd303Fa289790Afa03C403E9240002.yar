import "pe"

rule REVERSINGLABS_Cert_Blocklist_64Cd303Fa289790Afa03C403E9240002 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "86644ef8-4218-5a04-9655-c7d51729872d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6104-L6120"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f51556a8a12affbd7f7633bf8daa50e6332fa3d3448ea08853cf8ed28e593680"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MAITLAND TRIFECTA, INC." and pe.signatures[i].serial=="64:cd:30:3f:a2:89:79:0a:fa:03:c4:03:e9:24:00:02" and 1602723600<=pe.signatures[i].not_after)
}
