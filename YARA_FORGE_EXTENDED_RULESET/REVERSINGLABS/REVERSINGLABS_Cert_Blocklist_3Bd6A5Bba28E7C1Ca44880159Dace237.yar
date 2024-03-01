import "pe"

rule REVERSINGLABS_Cert_Blocklist_3Bd6A5Bba28E7C1Ca44880159Dace237 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c80245bd-908a-5b89-92e3-af0dd7bed63a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3396-L3412"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f885c782148947d09133a3cc65319e02204c21d6c6d911b360840f25f37601dc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TECHNO BEAVERS LIMITED" and pe.signatures[i].serial=="3b:d6:a5:bb:a2:8e:7c:1c:a4:48:80:15:9d:ac:e2:37" and 1563408000<=pe.signatures[i].not_after)
}
