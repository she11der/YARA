import "pe"

rule REVERSINGLABS_Cert_Blocklist_277Cd16De5D61B9398B645Afe41C09C7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d863faac-7b6e-5e1d-960f-8379347c6838"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8658-L8674"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "696467d699dec060b205f36f53dbe157b241823757d72798b35235d6530fd193"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE SIGN COMPANY LIMITED" and pe.signatures[i].serial=="27:7c:d1:6d:e5:d6:1b:93:98:b6:45:af:e4:1c:09:c7" and 1619049600<=pe.signatures[i].not_after)
}
