import "pe"

rule REVERSINGLABS_Cert_Blocklist_B2E730B0526F36Faf7D093D48D6D9997 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "eb82e05b-9aee-5ea7-88a5-8d186b8aafb8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5044-L5062"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f74cc94428d7739abf6ee76f6cbd53aa47cea815a014de0d786fe53b15f66201"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bamboo Connect s.r.o." and (pe.signatures[i].serial=="00:b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97" or pe.signatures[i].serial=="b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97") and 1597276800<=pe.signatures[i].not_after)
}
