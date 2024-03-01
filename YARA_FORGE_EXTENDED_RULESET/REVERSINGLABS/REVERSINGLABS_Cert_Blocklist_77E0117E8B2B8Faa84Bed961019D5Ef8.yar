import "pe"

rule REVERSINGLABS_Cert_Blocklist_77E0117E8B2B8Faa84Bed961019D5Ef8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2733cc5b-bc1f-5ba9-a2f4-50f472fc288e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2916-L2932"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bea94b9da8c176f22a66fe7a4545dcc3a38f727a75a0bc7920d9aece8e24b9b7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Reiner Wodey Informationssysteme" and pe.signatures[i].serial=="77:e0:11:7e:8b:2b:8f:aa:84:be:d9:61:01:9d:5e:f8" and 1383695999<=pe.signatures[i].not_after)
}
