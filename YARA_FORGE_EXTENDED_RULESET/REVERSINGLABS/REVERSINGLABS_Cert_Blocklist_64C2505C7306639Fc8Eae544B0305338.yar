import "pe"

rule REVERSINGLABS_Cert_Blocklist_64C2505C7306639Fc8Eae544B0305338 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b0e4057f-a0e7-5e2e-a47f-dc8188b6b506"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11254-L11270"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9b6fb002d603135391958668be0ef805e441928a035c9c4da4bb9915aa3086e8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MANILA Solution as" and pe.signatures[i].serial=="64:c2:50:5c:73:06:63:9f:c8:ea:e5:44:b0:30:53:38" and 1609418043<=pe.signatures[i].not_after)
}
