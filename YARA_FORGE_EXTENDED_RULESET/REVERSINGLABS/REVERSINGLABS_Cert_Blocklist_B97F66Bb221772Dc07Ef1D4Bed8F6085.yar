import "pe"

rule REVERSINGLABS_Cert_Blocklist_B97F66Bb221772Dc07Ef1D4Bed8F6085 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c83918d8-fe90-59dc-8f4e-0e7b10238780"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7444-L7462"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "794dc27ff9b2588d3f2c31cdb83e53616c604aa41da7d8c895034e1cf9da5dd8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "S-PRO d.o.o." and (pe.signatures[i].serial=="00:b9:7f:66:bb:22:17:72:dc:07:ef:1d:4b:ed:8f:60:85" or pe.signatures[i].serial=="b9:7f:66:bb:22:17:72:dc:07:ef:1d:4b:ed:8f:60:85") and 1614556800<=pe.signatures[i].not_after)
}
