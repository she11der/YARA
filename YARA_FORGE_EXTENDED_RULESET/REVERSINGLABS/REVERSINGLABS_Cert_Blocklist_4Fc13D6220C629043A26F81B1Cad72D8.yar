import "pe"

rule REVERSINGLABS_Cert_Blocklist_4Fc13D6220C629043A26F81B1Cad72D8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c2573adc-6580-58aa-a58c-c21bf6b79364"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1618-L1634"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5572c278f6c9be62b2bba09ea610fd170438c6893ee5283ff4a5b3bb2852b07b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Open Source Developer, meicun ge" and pe.signatures[i].serial=="4f:c1:3d:62:20:c6:29:04:3a:26:f8:1b:1c:ad:72:d8" and 1404172799<=pe.signatures[i].not_after)
}
