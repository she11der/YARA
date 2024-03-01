import "pe"

rule REVERSINGLABS_Cert_Blocklist_90E33C1068F54913315B6Ce9311141B9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "61c5d5ed-ca2c-5f71-893b-4c933b37fa27"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15498-L15516"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4a97171c6dfaa8d249ab0be1ce264b596d266ff4697d869a4d1f90cc0e2c49b7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GERMES, OOO" and (pe.signatures[i].serial=="00:90:e3:3c:10:68:f5:49:13:31:5b:6c:e9:31:11:41:b9" or pe.signatures[i].serial=="90:e3:3c:10:68:f5:49:13:31:5b:6c:e9:31:11:41:b9") and 1487635200<=pe.signatures[i].not_after)
}
