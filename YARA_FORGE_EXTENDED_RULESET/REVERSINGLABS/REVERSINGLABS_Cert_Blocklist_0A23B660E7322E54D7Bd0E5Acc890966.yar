import "pe"

rule REVERSINGLABS_Cert_Blocklist_0A23B660E7322E54D7Bd0E5Acc890966 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "daae5f42-59ff-5838-9444-93357eaa9d60"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6272-L6288"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "17996dd0ec81623dbd4eeea98f9bbe37c11c911ca840833ecb9301bb0a9ddb52"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ARTBUD RADOM SP Z O O" and pe.signatures[i].serial=="0a:23:b6:60:e7:32:2e:54:d7:bd:0e:5a:cc:89:09:66" and 1601254800<=pe.signatures[i].not_after)
}
