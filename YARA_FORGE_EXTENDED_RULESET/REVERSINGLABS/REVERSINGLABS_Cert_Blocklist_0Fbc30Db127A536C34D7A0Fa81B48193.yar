import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Fbc30Db127A536C34D7A0Fa81B48193 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "c755a6c1-e113-5513-9a61-87bf6d7dcb3e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2248-L2264"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6b109b5636aa297a6e07f9d9213f7f07a7767b58442d03dc2f34f8a9b3eaba2b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Megabit, OOO" and pe.signatures[i].serial=="0f:bc:30:db:12:7a:53:6c:34:d7:a0:fa:81:b4:81:93" and 1466121599<=pe.signatures[i].not_after)
}
