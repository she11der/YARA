import "pe"

rule REVERSINGLABS_Cert_Blocklist_2880A7F7Ff2D334Aa08744A8754Fab2C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b079b564-9284-59b6-9703-4e33f2b2c44d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1744-L1760"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "03c7e1251c44e8824ae3b648a95cf34f4c56db65d76806306a062a343981d87f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Garena Online Pte Ltd" and pe.signatures[i].serial=="28:80:a7:f7:ff:2d:33:4a:a0:87:44:a8:75:4f:ab:2c" and 1393891199<=pe.signatures[i].not_after)
}
