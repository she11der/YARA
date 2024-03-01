import "pe"

rule REVERSINGLABS_Cert_Blocklist_17D99Cc2F5B29522D422332E681F3E18 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0d0a58a4-353d-51f9-a739-a135d77357c9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7598-L7614"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "55cc1634cdc5209d68b98fdb0d9e97e0a34346cdcb10f243d13217cda01195f1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PKV Trading ApS" and pe.signatures[i].serial=="17:d9:9c:c2:f5:b2:95:22:d4:22:33:2e:68:1f:3e:18" and 1613088000<=pe.signatures[i].not_after)
}
