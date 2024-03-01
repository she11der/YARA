import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Ac5Ac5D323122E6D8E92D6E191B1432 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9a363a84-c21c-5afe-9812-9ce16962b28a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13912-L13928"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d5e62d3cdfacfaea70f9ee11230501bb9c4099508077d50a2a143cb69476f02a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Certified Software" and pe.signatures[i].serial=="0a:c5:ac:5d:32:31:22:e6:d8:e9:2d:6e:19:1b:14:32" and 1140134400<=pe.signatures[i].not_after)
}
