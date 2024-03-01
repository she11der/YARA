import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Bf27695Fd20B588F2B2F173B6Caf2Ba : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a3e6923a-f2c4-5d7c-aeab-bdb7fe03c597"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10936-L10952"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "94d8739761b6a8ee91550be47432b046609b076aab6e57996de123a0fcaba73e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Game Warriors Limited" and pe.signatures[i].serial=="7b:f2:76:95:fd:20:b5:88:f2:b2:f1:73:b6:ca:f2:ba" and 1662112800<=pe.signatures[i].not_after)
}
