import "pe"

rule REVERSINGLABS_Cert_Blocklist_629D120Dd84F9C1688D4Da40366Fab7A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7e6249ba-3a4f-5096-be32-779e73c88221"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2806-L2822"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "187f6ef0de869500526d1b0d5c6f6762b0a939e06781e633a602834687c64023"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Delta Controls" and pe.signatures[i].serial=="62:9d:12:0d:d8:4f:9c:16:88:d4:da:40:36:6f:ab:7a" and 1306799999<=pe.signatures[i].not_after)
}
