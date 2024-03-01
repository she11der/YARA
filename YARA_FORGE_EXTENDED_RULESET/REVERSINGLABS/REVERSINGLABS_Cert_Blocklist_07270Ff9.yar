import "pe"

rule REVERSINGLABS_Cert_Blocklist_07270Ff9 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "fcd2d82a-b51d-53ff-bfae-3c83147c1903"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L765-L781"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8f0da7c330464184fa1d5bf8d51dd8ad2e8637710a36972dcab03629cb57e910"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DigiNotar Cyber CA" and pe.signatures[i].serial=="07:27:0f:f9" and 1308182400<=pe.signatures[i].not_after)
}
