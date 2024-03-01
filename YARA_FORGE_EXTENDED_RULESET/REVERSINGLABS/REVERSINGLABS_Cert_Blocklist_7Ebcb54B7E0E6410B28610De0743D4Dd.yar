import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Ebcb54B7E0E6410B28610De0743D4Dd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "84140bbd-23a0-5355-9d1a-918cc93c3352"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9168-L9184"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c9444ff9e13192bf300afac12554bc4cc2defb37bb5b57906b6163db378c515a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SIA \"MWorx\"" and pe.signatures[i].serial=="7e:bc:b5:4b:7e:0e:64:10:b2:86:10:de:07:43:d4:dd" and 1625616000<=pe.signatures[i].not_after)
}
