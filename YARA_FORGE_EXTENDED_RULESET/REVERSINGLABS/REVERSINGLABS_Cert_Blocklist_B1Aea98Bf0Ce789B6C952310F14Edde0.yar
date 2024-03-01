import "pe"

rule REVERSINGLABS_Cert_Blocklist_B1Aea98Bf0Ce789B6C952310F14Edde0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f039f379-e3d5-56bd-83b7-016881538017"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6048-L6066"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6e78750d6aca91e9e6d8f2651a5682ccdab5cd20ee3a74e1f8582eb7bc45d614"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Absolut LLC" and (pe.signatures[i].serial=="00:b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0" or pe.signatures[i].serial=="b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0") and 1602612570<=pe.signatures[i].not_after)
}
