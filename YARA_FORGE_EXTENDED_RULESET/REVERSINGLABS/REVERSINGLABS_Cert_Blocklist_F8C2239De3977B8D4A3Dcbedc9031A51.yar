import "pe"

rule REVERSINGLABS_Cert_Blocklist_F8C2239De3977B8D4A3Dcbedc9031A51 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "3e102d0a-30e3-5f0a-9b67-a5fd15117e69"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1272-L1288"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "aa4f39790bc58b0a50e05e7670abad654d7f3d73e500bd5f054fece4a979ebfa"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Adobe Systems" and pe.signatures[i].serial=="f8:c2:23:9d:e3:97:7b:8d:4a:3d:cb:ed:c9:03:1a:51" and 1341792000<=pe.signatures[i].not_after)
}
