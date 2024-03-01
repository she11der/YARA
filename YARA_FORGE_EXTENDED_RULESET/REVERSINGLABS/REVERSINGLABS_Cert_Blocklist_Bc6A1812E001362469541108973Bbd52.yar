import "pe"

rule REVERSINGLABS_Cert_Blocklist_Bc6A1812E001362469541108973Bbd52 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ac5ac6d7-898b-5547-8d35-a483f20edcd6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12330-L12348"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9b678e9fb1e1eda3ac8e027b5e449af446de4379fea46ef7ff820240c73795ee"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and (pe.signatures[i].serial=="00:bc:6a:18:12:e0:01:36:24:69:54:11:08:97:3b:bd:52" or pe.signatures[i].serial=="bc:6a:18:12:e0:01:36:24:69:54:11:08:97:3b:bd:52") and 1623801600<=pe.signatures[i].not_after)
}
