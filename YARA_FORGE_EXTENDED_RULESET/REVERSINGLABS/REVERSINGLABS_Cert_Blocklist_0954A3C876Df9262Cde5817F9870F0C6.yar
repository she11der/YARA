import "pe"

rule REVERSINGLABS_Cert_Blocklist_0954A3C876Df9262Cde5817F9870F0C6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "89f3a334-cd2f-51b9-83b2-2baca3c59ba5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13004-L13020"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "164b064a9df31d4a122236dfee7b713417a44d47a7f304b2bf55686a7f038feb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dialer Access" and pe.signatures[i].serial=="09:54:a3:c8:76:df:92:62:cd:e5:81:7f:98:70:f0:c6" and 1160438400<=pe.signatures[i].not_after)
}
