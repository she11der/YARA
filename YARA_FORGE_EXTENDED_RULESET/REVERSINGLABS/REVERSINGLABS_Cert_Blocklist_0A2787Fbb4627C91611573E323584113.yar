import "pe"

rule REVERSINGLABS_Cert_Blocklist_0A2787Fbb4627C91611573E323584113 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "64848927-6a60-5ea9-bae5-7d15c3f35ca6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10662-L10678"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "efa352beafb56b95a89554bc8929f8e01a4da46eef1f6cf8a1487a2a06bc1b3e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "exxon.com" and pe.signatures[i].serial=="0a:27:87:fb:b4:62:7c:91:61:15:73:e3:23:58:41:13" and 1640822400<=pe.signatures[i].not_after)
}
