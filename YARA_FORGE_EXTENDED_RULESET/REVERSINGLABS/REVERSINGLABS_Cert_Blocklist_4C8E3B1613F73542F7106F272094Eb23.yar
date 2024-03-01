import "pe"

rule REVERSINGLABS_Cert_Blocklist_4C8E3B1613F73542F7106F272094Eb23 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "06f79efe-134e-5941-80fe-3b6482ac9668"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2212-L2228"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "15c21b783409d904a0b4971dbdcbd0740083d13f3c633ee77c87df46d3aca748"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ADD Audit" and pe.signatures[i].serial=="4c:8e:3b:16:13:f7:35:42:f7:10:6f:27:20:94:eb:23" and 1472687999<=pe.signatures[i].not_after)
}
