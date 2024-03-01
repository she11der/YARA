import "pe"

rule REVERSINGLABS_Cert_Blocklist_0C76Da9C910C4E2C9Efe15D058933C4C : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "a9b06d49-1ab2-539e-bd1f-16da40b654b2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L873-L889"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "883e93bff42161ba68f69fb17f7e78377d7f3cb6b6cdf72cffb4166466f8bc7b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DigiNotar Root CA" and pe.signatures[i].serial=="0c:76:da:9c:91:0c:4e:2c:9e:fe:15:d0:58:93:3c:4c" and 1308182400<=pe.signatures[i].not_after)
}
