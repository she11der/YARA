import "pe"

rule REVERSINGLABS_Cert_Blocklist_68E1B2C210B19Bb1F2A24176709B165B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e17bf185-3dfc-5a2f-a87f-525ac0e4084b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13838-L13854"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8e88ad992c58d37ff1ac34e2d9cf121f3bc692ae78c0ad79140974abdec2f317"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="68:e1:b2:c2:10:b1:9b:b1:f2:a2:41:76:70:9b:16:5b" and 1474502400<=pe.signatures[i].not_after)
}
