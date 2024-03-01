import "pe"

rule REVERSINGLABS_Cert_Blocklist_4D29757C4Fbfc32B97091D96E3723002 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e1834597-4e45-5866-97f4-e00c79190930"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15350-L15366"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "78ede4b02cb1b07500cd0c4f1f33da598938940d0f58430edda00d79b19b16a5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="4d:29:75:7c:4f:bf:c3:2b:97:09:1d:96:e3:72:30:02" and 1474848000<=pe.signatures[i].not_after)
}
