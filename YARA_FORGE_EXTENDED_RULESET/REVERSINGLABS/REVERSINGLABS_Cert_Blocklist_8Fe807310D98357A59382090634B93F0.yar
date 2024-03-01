import "pe"

rule REVERSINGLABS_Cert_Blocklist_8Fe807310D98357A59382090634B93F0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "690e7919-0344-5bd1-849f-e7bfe2f19276"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7424-L7442"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0ec56bd4783c854efef863050ff729fd99efa98b7b19e04e56a080ee3e75cd90"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MAVE MEDIA" and (pe.signatures[i].serial=="00:8f:e8:07:31:0d:98:35:7a:59:38:20:90:63:4b:93:f0" or pe.signatures[i].serial=="8f:e8:07:31:0d:98:35:7a:59:38:20:90:63:4b:93:f0") and 1613433600<=pe.signatures[i].not_after)
}
