import "pe"

rule REVERSINGLABS_Cert_Blocklist_1B7B54E0Dd4D7E45A0B46834De52658D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "376da749-3cd4-5e37-b1ee-013e839f98ce"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14876-L14892"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5febbce8c39440bfc4846f509f0b1dd4f71a8b4dc24fa18afb561d26e53c2446"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="1b:7b:54:e0:dd:4d:7e:45:a0:b4:68:34:de:52:65:8d" and 1476662400<=pe.signatures[i].not_after)
}
