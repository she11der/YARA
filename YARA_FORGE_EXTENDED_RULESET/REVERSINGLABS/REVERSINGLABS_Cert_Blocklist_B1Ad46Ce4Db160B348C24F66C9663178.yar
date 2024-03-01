import "pe"

rule REVERSINGLABS_Cert_Blocklist_B1Ad46Ce4Db160B348C24F66C9663178 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "df34eb28-18ec-568b-8257-0b2f7959868c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1398-L1414"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "59ce2b7a2e881853d07446b3dda74b296f2be09651364d0e131552cf76dab751"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Adobe Systems" and pe.signatures[i].serial=="b1:ad:46:ce:4d:b1:60:b3:48:c2:4f:66:c9:66:31:78" and 1341792000<=pe.signatures[i].not_after)
}
