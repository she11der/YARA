import "pe"

rule REVERSINGLABS_Cert_Blocklist_661Ba8F3C9D1B348413484E9A49502F7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a0c501c9-a856-55b6-b845-aeab4db5ab51"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4930-L4948"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4840b311c1e2c0ae14bb2cf6fa8d96ab1a434ceac861db540697f3aed1a6833f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Unique Digital Services Ltd." and (pe.signatures[i].serial=="00:66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7" or pe.signatures[i].serial=="66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7") and 1594942800<=pe.signatures[i].not_after)
}
