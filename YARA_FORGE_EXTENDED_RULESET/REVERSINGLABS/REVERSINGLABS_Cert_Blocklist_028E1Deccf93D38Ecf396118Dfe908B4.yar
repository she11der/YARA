import "pe"

rule REVERSINGLABS_Cert_Blocklist_028E1Deccf93D38Ecf396118Dfe908B4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6dfb0181-299f-5a28-b647-137d75f747a6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L225-L241"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b07c797652ef19c7e0b23c3eddbbbf2700160d743d71a0005b950160474638d8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fortuna Games Co., Ltd." and pe.signatures[i].serial=="02:8e:1d:ec:cf:93:d3:8e:cf:39:61:18:df:e9:08:b4" and 1392163199<=pe.signatures[i].not_after)
}
