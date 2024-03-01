import "pe"

rule REVERSINGLABS_Cert_Blocklist_4842Afad00904Ed8C98811E652Ccb3B7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f09723aa-85a6-5d96-a71e-94f0e0a0f23c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3288-L3304"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2b5c7c13369c7b89f1ea5474de3644a12bf6412cb3fa8ade5b66de280fb10cbf"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\"VERY EXCLUSIVE LTD\"" and pe.signatures[i].serial=="48:42:af:ad:00:90:4e:d8:c9:88:11:e6:52:cc:b3:b7" and 1545177600<=pe.signatures[i].not_after)
}
