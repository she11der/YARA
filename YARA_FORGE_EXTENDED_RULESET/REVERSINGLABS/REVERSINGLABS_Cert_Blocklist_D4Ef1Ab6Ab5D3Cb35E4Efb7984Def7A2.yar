import "pe"

rule REVERSINGLABS_Cert_Blocklist_D4Ef1Ab6Ab5D3Cb35E4Efb7984Def7A2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "41b2e05f-1dcd-5ebc-97da-275512deaf72"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8492-L8510"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ecc2f6bfda1a0afd016f0a5183c0d1cdfe5d5e06c893a7d9a3d7cb7f9bc4bf16"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REIGN BROS ApS" and (pe.signatures[i].serial=="00:d4:ef:1a:b6:ab:5d:3c:b3:5e:4e:fb:79:84:de:f7:a2" or pe.signatures[i].serial=="d4:ef:1a:b6:ab:5d:3c:b3:5e:4e:fb:79:84:de:f7:a2") and 1611187200<=pe.signatures[i].not_after)
}
