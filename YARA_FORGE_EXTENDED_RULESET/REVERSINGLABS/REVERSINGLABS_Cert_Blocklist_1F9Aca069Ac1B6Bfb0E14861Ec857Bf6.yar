import "pe"

rule REVERSINGLABS_Cert_Blocklist_1F9Aca069Ac1B6Bfb0E14861Ec857Bf6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b78e3bc2-5b65-507a-9183-148f97baa3e8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14278-L14294"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d7c9a471455768a00deeb73900bf80a98f0b2c9da1fd09d568e2998deaf404d2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yuanyuan Zhang" and pe.signatures[i].serial=="1f:9a:ca:06:9a:c1:b6:bf:b0:e1:48:61:ec:85:7b:f6" and 1477440000<=pe.signatures[i].not_after)
}
