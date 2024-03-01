import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Dcd19A94535F034Ee36Af4676740633 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c09778b6-17c9-5b24-8977-1bd998083c23"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7032-L7048"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7079d4f1973ad4de21e1f88282c94b11c4d63f8bad12b35ef76a481e154d9da3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Toko Saya ApS" and pe.signatures[i].serial=="7d:cd:19:a9:45:35:f0:34:ee:36:af:46:76:74:06:33" and 1609200000<=pe.signatures[i].not_after)
}
