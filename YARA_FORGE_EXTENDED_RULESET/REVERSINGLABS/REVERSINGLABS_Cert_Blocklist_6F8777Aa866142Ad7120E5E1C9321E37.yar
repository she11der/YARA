import "pe"

rule REVERSINGLABS_Cert_Blocklist_6F8777Aa866142Ad7120E5E1C9321E37 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ace8a8b4-5288-56c4-bd47-9eb42ea41ecb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12554-L12570"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ca3ff0c7192ba90932d35d053712816555dea051ce15d29a7ccf4e37da989899"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CLOUD SOFTWARE LINE CO., LTD." and pe.signatures[i].serial=="6f:87:77:aa:86:61:42:ad:71:20:e5:e1:c9:32:1e:37" and 1629676800<=pe.signatures[i].not_after)
}
