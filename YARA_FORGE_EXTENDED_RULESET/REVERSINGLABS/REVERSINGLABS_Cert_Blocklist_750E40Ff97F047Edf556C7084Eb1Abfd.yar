import "pe"

rule REVERSINGLABS_Cert_Blocklist_750E40Ff97F047Edf556C7084Eb1Abfd : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "7ae4ba81-82be-57f9-aa8c-0e5c30e412c6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1019-L1035"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "21c2468905514e1725a206814b0c61c576cf7f97f184bac857bca9283f49a957"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Microsoft Corporation" and pe.signatures[i].serial=="75:0e:40:ff:97:f0:47:ed:f5:56:c7:08:4e:b1:ab:fd" and 980899199<=pe.signatures[i].not_after)
}
