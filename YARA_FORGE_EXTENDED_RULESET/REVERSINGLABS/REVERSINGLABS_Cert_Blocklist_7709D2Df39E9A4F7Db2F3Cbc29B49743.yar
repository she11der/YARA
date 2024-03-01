import "pe"

rule REVERSINGLABS_Cert_Blocklist_7709D2Df39E9A4F7Db2F3Cbc29B49743 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7227daa3-453d-5bb8-804c-8a97cd0d81c6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5232-L5248"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c9ade45e0f9fb737a08ffa94d1fff89471a1cbcbacc139730fab88e382226d0b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Grina LLC" and pe.signatures[i].serial=="77:09:d2:df:39:e9:a4:f7:db:2f:3c:bc:29:b4:97:43" and 1556353331<=pe.signatures[i].not_after)
}
