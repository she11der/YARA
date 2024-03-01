import "pe"

rule REVERSINGLABS_Cert_Blocklist_6171990Ba1C8E71049Ebb296A35Bd160 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f81697ca-e49a-5a3d-9e0f-6192159e098b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9222-L9238"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e922bb850b7c5c70db80e6a2b99310eac48d3b10b94a7259899facd681916bfa"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OWLNET LIMITED" and pe.signatures[i].serial=="61:71:99:0b:a1:c8:e7:10:49:eb:b2:96:a3:5b:d1:60" and 1620000000<=pe.signatures[i].not_after)
}
