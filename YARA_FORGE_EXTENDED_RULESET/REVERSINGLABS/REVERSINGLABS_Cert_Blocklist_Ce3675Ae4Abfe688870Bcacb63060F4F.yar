import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ce3675Ae4Abfe688870Bcacb63060F4F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "586c9de9-e1b0-5d17-9783-c9e18dfdf463"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3656-L3674"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0c6f2ef55bef283a3f915fd8c1ced27c3c665f7f490caeea0f180c2d7fa2b2b5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO \"MPS\"" and (pe.signatures[i].serial=="00:ce:36:75:ae:4a:bf:e6:88:87:0b:ca:cb:63:06:0f:4f" or pe.signatures[i].serial=="ce:36:75:ae:4a:bf:e6:88:87:0b:ca:cb:63:06:0f:4f") and 1582675200<=pe.signatures[i].not_after)
}
