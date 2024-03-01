import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Ed1847A2Ae5D71Def1E833Fddd33D38 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "11fd3bbe-5d15-57b7-a461-fc9c90046dbc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5992-L6008"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0ec5eb8ff1f630284fabfba5c58dd563d471343ace718f79dad08cfe75c3070d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SNAB-RESURS, OOO" and pe.signatures[i].serial=="0e:d1:84:7a:2a:e5:d7:1d:ef:1e:83:3f:dd:d3:3d:38" and 1598662800<=pe.signatures[i].not_after)
}
