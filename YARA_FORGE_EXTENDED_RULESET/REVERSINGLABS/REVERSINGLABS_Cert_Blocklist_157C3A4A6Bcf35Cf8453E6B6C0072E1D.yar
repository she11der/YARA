import "pe"

rule REVERSINGLABS_Cert_Blocklist_157C3A4A6Bcf35Cf8453E6B6C0072E1D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing GovRAT malware."
		author = "ReversingLabs"
		id = "4bae3fb2-7e30-598e-8708-b985697bf63a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1490-L1506"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2a68051ab6d0b967f08e44d91b9f13d75587ea0f16e2a5536ccf5898445e1a58"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Favorite-III" and pe.signatures[i].serial=="15:7c:3a:4a:6b:cf:35:cf:84:53:e6:b6:c0:07:2e:1d" and 1404172799<=pe.signatures[i].not_after)
}
