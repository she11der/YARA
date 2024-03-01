import "pe"

rule REVERSINGLABS_Cert_Blocklist_0619C5E39A4Fc60A32F9B07F6A4Ca328 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ae3ef9cf-4b67-5cb8-9c9b-3edb95da222c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16690-L16706"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "75e3dfd593d7fdc268de54430be617c015957a624f2ca36bc0036d4cbde5b686"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yuanyuan Zhang" and pe.signatures[i].serial=="06:19:c5:e3:9a:4f:c6:0a:32:f9:b0:7f:6a:4c:a3:28" and 1475884800<=pe.signatures[i].not_after)
}
