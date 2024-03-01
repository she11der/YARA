import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Ecd460Ce14Bd8Ef2926Da2Cd9A44176 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "94128695-0206-5c04-b792-34400f8ce890"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12648-L12664"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "58fa244c125415ef7a3cf0feb79add4db7c84f94c23e5d27e840fb17c18d67ef"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rabah Azrarak" and pe.signatures[i].serial=="0e:cd:46:0c:e1:4b:d8:ef:29:26:da:2c:d9:a4:41:76" and 1463035153<=pe.signatures[i].not_after)
}
