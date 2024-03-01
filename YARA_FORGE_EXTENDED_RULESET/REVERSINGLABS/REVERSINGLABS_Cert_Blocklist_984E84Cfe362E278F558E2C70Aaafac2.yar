import "pe"

rule REVERSINGLABS_Cert_Blocklist_984E84Cfe362E278F558E2C70Aaafac2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "180f1209-7031-50fb-b1fc-3d357f2b73a1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11744-L11762"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e7a8f3dff77121df53d5f932f861e15208b0607ba77712f40927bc14b17a53cd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Arctic Nights \\xC3\\x84k\\xC3\\xA4slompolo Oy" and (pe.signatures[i].serial=="00:98:4e:84:cf:e3:62:e2:78:f5:58:e2:c7:0a:aa:fa:c2" or pe.signatures[i].serial=="98:4e:84:cf:e3:62:e2:78:f5:58:e2:c7:0a:aa:fa:c2") and 1640304000<=pe.signatures[i].not_after)
}
