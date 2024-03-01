import "pe"

rule REVERSINGLABS_Cert_Blocklist_57D7153A89Bbf4729Be87F3C927043Aa : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9b778a20-8a0c-5c9f-8cc3-9e5054713e13"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L207-L223"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a8de7951bd25c8a9346ef341d8bf9c9147f9fa6913e952be40fb43d3d7a370c1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Open Source Developer, zhenganjun" and pe.signatures[i].serial=="57:d7:15:3a:89:bb:f4:72:9b:e8:7f:3c:92:70:43:aa" and 1469059200<=pe.signatures[i].not_after)
}
