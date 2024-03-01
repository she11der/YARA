import "pe"

rule REVERSINGLABS_Cert_Blocklist_3A6Ccabb1C62F3Be3Eb03869Fa43Dc4A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b16f7bb7-88fe-5f8f-9592-8d309f556419"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2394-L2410"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ccb603c8a5f4fb63876e78d763f80a97098c23aa10673c7b04a48026268f57d3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\xB8\\xB8\\xE5\\xB7\\x9E\\xE9\\xAA\\x8F\\xE6\\x99\\xAF\\xE9\\x80\\x9A\\xE8\\x81\\x94\\xE6\\x95\\xB0\\xE5\\xAD\\x97\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="3a:6c:ca:bb:1c:62:f3:be:3e:b0:38:69:fa:43:dc:4a" and 1259798399<=pe.signatures[i].not_after)
}
