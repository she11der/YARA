import "pe"

rule REVERSINGLABS_Cert_Blocklist_4Ba7Fb8Ee1Deff8F4A1525E1E0580057 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "af912c64-334d-51f5-8ca4-707fcec512ba"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1326-L1342"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "324157b9fec2653cb8874c7a1a5b6e39b121992cd52856b8c4a2a8b7cee86a69"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Adobe Systems" and pe.signatures[i].serial=="4b:a7:fb:8e:e1:de:ff:8f:4a:15:25:e1:e0:58:00:57" and 1341792000<=pe.signatures[i].not_after)
}
