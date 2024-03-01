import "pe"

rule REVERSINGLABS_Cert_Blocklist_E5Ad42C509A7C24605530D35832C091E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "29b1803e-90ee-5390-9548-20b24a3de218"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5692-L5710"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2d57d1c171734d0da167ce7eba47aecd88cd15063488d79659804c6c2fae00a2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VESNA, OOO" and (pe.signatures[i].serial=="00:e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e" or pe.signatures[i].serial=="e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e") and 1600786458<=pe.signatures[i].not_after)
}
