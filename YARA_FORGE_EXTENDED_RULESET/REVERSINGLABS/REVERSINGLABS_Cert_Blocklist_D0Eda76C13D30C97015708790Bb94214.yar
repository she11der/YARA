import "pe"

rule REVERSINGLABS_Cert_Blocklist_D0Eda76C13D30C97015708790Bb94214 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "aa323bac-a9f5-560f-b44a-3cf2b26351bb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8676-L8694"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2112ebfb7c9ebbbccb20cefcd23bb49142da770feb16ee8eef5eb27646226785"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LAEN ApS" and (pe.signatures[i].serial=="00:d0:ed:a7:6c:13:d3:0c:97:01:57:08:79:0b:b9:42:14" or pe.signatures[i].serial=="d0:ed:a7:6c:13:d3:0c:97:01:57:08:79:0b:b9:42:14") and 1619136000<=pe.signatures[i].not_after)
}
