import "pe"

rule REVERSINGLABS_Cert_Blocklist_05E2E6A4Cd09Ea54D665B075Fe22A256 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "824c6b2f-081a-5f38-b949-d802f59e6ced"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L27-L43"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "43da21d9c7ae9bfcc7fe4ee69f9d46cbce1954785d56c1d424b36deb8afe592e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "*.google.com" and pe.signatures[i].serial=="05:e2:e6:a4:cd:09:ea:54:d6:65:b0:75:fe:22:a2:56" and 1308182400<=pe.signatures[i].not_after)
}
