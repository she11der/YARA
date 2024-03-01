import "pe"

rule REVERSINGLABS_Cert_Blocklist_309D2E115F1Fe2993Ee2E063 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7182f3f2-7b2a-5c29-b7a9-607feafbe570"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15480-L15496"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "15fdb95fe5429cdc0263615c2b7c90d21f37b52954c5ce568c1293cd3a544730"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="30:9d:2e:11:5f:1f:e2:99:3e:e2:e0:63" and 1467102525<=pe.signatures[i].not_after)
}
