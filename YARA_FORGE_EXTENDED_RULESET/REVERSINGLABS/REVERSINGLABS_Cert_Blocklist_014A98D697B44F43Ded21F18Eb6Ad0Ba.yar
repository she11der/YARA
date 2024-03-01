import "pe"

rule REVERSINGLABS_Cert_Blocklist_014A98D697B44F43Ded21F18Eb6Ad0Ba : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4fcd4e89-658c-593b-8f94-edd5df19da6e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6388-L6404"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9f1cc61b944974696113912bc1d1a0b45b9911fa4d6de382a48c0d22d2d20953"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Hillcoe Software Inc." and pe.signatures[i].serial=="01:4a:98:d6:97:b4:4f:43:de:d2:1f:18:eb:6a:d0:ba" and 1605364760<=pe.signatures[i].not_after)
}
