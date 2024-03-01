import "pe"

rule REVERSINGLABS_Cert_Blocklist_Dbb14Dcf973Eada14Ece7Ea79C895C11 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "139f2e4f-7997-5cfd-aba2-dcf8d7525f5e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1254-L1270"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c73c83f5cb6d840b887e1aa41e96a29529f975434ac27a5aa57f2e14b342f63d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Adobe Systems" and pe.signatures[i].serial=="db:b1:4d:cf:97:3e:ad:a1:4e:ce:7e:a7:9c:89:5c:11" and 1341792000<=pe.signatures[i].not_after)
}
