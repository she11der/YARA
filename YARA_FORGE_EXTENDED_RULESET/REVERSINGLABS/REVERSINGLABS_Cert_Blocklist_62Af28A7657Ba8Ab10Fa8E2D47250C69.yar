import "pe"

rule REVERSINGLABS_Cert_Blocklist_62Af28A7657Ba8Ab10Fa8E2D47250C69 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing GovRAT malware."
		author = "ReversingLabs"
		id = "cba20a1b-5d24-5a1f-8f2f-8c47add846d6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1454-L1470"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c3c034cb4e2c65e2269fbfd9c045eb294badde60389ae62ed694ea4d61c5eb35"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AFINA Fintek" and pe.signatures[i].serial=="62:af:28:a7:65:7b:a8:ab:10:fa:8e:2d:47:25:0c:69" and 1404172799<=pe.signatures[i].not_after)
}
