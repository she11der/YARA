import "pe"

rule REVERSINGLABS_Cert_Blocklist_Df2547B2Cab5689A81D61De80Eaaa3A2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1e76a088-b0f2-54d6-b730-77552c74d7bd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10824-L10842"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cde89ae5b77ff6833fe642bdd74e81763ef068e31c07e7881906e4e4a5939942"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FORWARD MUSIC AGENCY SRL" and (pe.signatures[i].serial=="00:df:25:47:b2:ca:b5:68:9a:81:d6:1d:e8:0e:aa:a3:a2" or pe.signatures[i].serial=="df:25:47:b2:ca:b5:68:9a:81:d6:1d:e8:0e:aa:a3:a2") and 1657756800<=pe.signatures[i].not_after)
}
