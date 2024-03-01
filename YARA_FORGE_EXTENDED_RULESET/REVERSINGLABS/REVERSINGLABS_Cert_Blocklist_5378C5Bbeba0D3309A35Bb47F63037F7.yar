import "pe"

rule REVERSINGLABS_Cert_Blocklist_5378C5Bbeba0D3309A35Bb47F63037F7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7f367505-d7c1-5b8c-83bd-df3fec789d12"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5864-L5882"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a96acf93ca6da4d3bf5177b51996825cd3ea70443577622deccdd11fde579c31"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OORT inc." and (pe.signatures[i].serial=="00:53:78:c5:bb:eb:a0:d3:30:9a:35:bb:47:f6:30:37:f7" or pe.signatures[i].serial=="53:78:c5:bb:eb:a0:d3:30:9a:35:bb:47:f6:30:37:f7") and 1601427420<=pe.signatures[i].not_after)
}
