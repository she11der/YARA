import "pe"

rule REVERSINGLABS_Cert_Blocklist_73Bff2Fb714F986C1707165F0B0F2E0E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f014b446-0ddc-51df-898c-200bd60181a0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14040-L14056"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d79ab926cbc0049d39f5f4c6e57afc71b1a30311a4816fdb66a9c2e257cc84af"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Tecnopolis Consulting Ltd" and pe.signatures[i].serial=="73:bf:f2:fb:71:4f:98:6c:17:07:16:5f:0b:0f:2e:0e" and 1090886400<=pe.signatures[i].not_after)
}
