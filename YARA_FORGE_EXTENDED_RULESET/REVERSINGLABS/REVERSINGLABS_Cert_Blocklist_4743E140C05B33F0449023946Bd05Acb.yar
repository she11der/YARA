import "pe"

rule REVERSINGLABS_Cert_Blocklist_4743E140C05B33F0449023946Bd05Acb : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f783bad3-f350-5a74-8e3f-5b7220e4de8f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7960-L7976"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "69ce1512d7df4926ee2b470b18fbe51a2aa81e07b37b2536617d6353045e0d19"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STROI RENOV SARL" and pe.signatures[i].serial=="47:43:e1:40:c0:5b:33:f0:44:90:23:94:6b:d0:5a:cb" and 1607644800<=pe.signatures[i].not_after)
}
