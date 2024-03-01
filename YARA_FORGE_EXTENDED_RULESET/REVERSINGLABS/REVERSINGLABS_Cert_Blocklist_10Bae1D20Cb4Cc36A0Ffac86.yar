import "pe"

rule REVERSINGLABS_Cert_Blocklist_10Bae1D20Cb4Cc36A0Ffac86 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a07d1c35-0026-526a-bf08-e6b07008da03"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13986-L14002"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "44e91fbf4da8e81859a21408ee9f1971f1e8f48d22553fcaa6469156d4a0670b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="10:ba:e1:d2:0c:b4:cc:36:a0:ff:ac:86" and 1476773830<=pe.signatures[i].not_after)
}
