import "pe"

rule REVERSINGLABS_Cert_Blocklist_Df5121Dc99D1Ab6B7E5229F6832123Ef : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8dfc50be-7316-5a52-937b-4551aa642b7e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15406-L15424"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3b5e5b81890f1dea3dc0858cade54e7f88a21861818be79c3e7fba066f80d491"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "INC SALYUT" and (pe.signatures[i].serial=="00:df:51:21:dc:99:d1:ab:6b:7e:52:29:f6:83:21:23:ef" or pe.signatures[i].serial=="df:51:21:dc:99:d1:ab:6b:7e:52:29:f6:83:21:23:ef") and 1613433600<=pe.signatures[i].not_after)
}
