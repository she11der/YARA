import "pe"

rule REVERSINGLABS_Cert_Blocklist_142Aac4217E22B525C8587589773Ba9B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "488be2f7-e3d4-51e3-b7bb-142caa7b2bd5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12030-L12046"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f169925c27f5e0f8d5f658b83d1b9fa4548c4443b16bd4d7f87aa2b8e44bf06b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "A.B. gostinstvo trgovina posredni\\xC5\\xA1tvo in druge storitve, d.o.o." and pe.signatures[i].serial=="14:2a:ac:42:17:e2:2b:52:5c:85:87:58:97:73:ba:9b" and 1614124800<=pe.signatures[i].not_after)
}
