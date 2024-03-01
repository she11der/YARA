import "pe"

rule REVERSINGLABS_Cert_Blocklist_04D6B8Cc6Dce353Fcf3Ae8A532Be7255 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "937dd780-52f7-5f27-ac2e-a0245997d449"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1924-L1940"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a316ad7f554428d02a850fb3bb04f349d30ecd2ccd4597e7a63461bf5e866e6f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MADERA" and pe.signatures[i].serial=="04:d6:b8:cc:6d:ce:35:3f:cf:3a:e8:a5:32:be:72:55" and 1451692799<=pe.signatures[i].not_after)
}
