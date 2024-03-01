import "pe"

rule REVERSINGLABS_Cert_Blocklist_24Af70B5D17A63Ad053E5821 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "034228b3-1864-5a76-ad9d-531778be10ec"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13276-L13292"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d78f709067c83169484d9dd6e1dd8a88852362da028551d4e55e5703a22e04a7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="24:af:70:b5:d1:7a:63:ad:05:3e:58:21" and 1474179615<=pe.signatures[i].not_after)
}
