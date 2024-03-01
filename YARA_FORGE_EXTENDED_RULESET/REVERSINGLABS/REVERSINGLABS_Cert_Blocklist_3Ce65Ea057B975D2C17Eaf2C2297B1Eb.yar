import "pe"

rule REVERSINGLABS_Cert_Blocklist_3Ce65Ea057B975D2C17Eaf2C2297B1Eb : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f86fbd6f-1635-56d7-b390-e067f81b8705"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14368-L14384"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e17988cb2503e285cfe2ea74d7bc61c577d828e14fd5d8d8062e469dc75c449e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TRANS LTD" and pe.signatures[i].serial=="3c:e6:5e:a0:57:b9:75:d2:c1:7e:af:2c:22:97:b1:eb" and 1528243200<=pe.signatures[i].not_after)
}
