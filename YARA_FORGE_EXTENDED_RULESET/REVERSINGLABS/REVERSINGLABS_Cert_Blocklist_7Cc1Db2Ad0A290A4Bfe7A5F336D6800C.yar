import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Cc1Db2Ad0A290A4Bfe7A5F336D6800C : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "89bc7c99-dea2-50ce-a0d2-4292c14d049e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L81-L97"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c9f91edb525a02041bc20dff25ec58323f8fabd4d2a2eca63238ecb10ccef2a6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bit9, Inc" and pe.signatures[i].serial=="7c:c1:db:2a:d0:a2:90:a4:bf:e7:a5:f3:36:d6:80:0c" and 1342051200<=pe.signatures[i].not_after)
}
