import "pe"

rule REVERSINGLABS_Cert_Blocklist_5E15205F180442Cc6C3C0F03E1A33D9F : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "4a0d995a-37df-52a4-a66f-4bc6c290c10a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2194-L2210"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1ca238b5da4ff9940425c99f55542c931ccdf0ea3b0a2acbf00ffbbb54171ae0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ziber Ltd" and pe.signatures[i].serial=="5e:15:20:5f:18:04:42:cc:6c:3c:0f:03:e1:a3:3d:9f" and 1498607999<=pe.signatures[i].not_after)
}
