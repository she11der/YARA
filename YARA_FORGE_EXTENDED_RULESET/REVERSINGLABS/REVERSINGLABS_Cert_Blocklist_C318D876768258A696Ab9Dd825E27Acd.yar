import "pe"

rule REVERSINGLABS_Cert_Blocklist_C318D876768258A696Ab9Dd825E27Acd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c6e93547-5be0-5303-b537-655db3d78ad4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11556-L11574"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "691b57929c93d14f8700e0e61170b9248499fd36b80aec90f2054c32d6a3a9eb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Genezis" and (pe.signatures[i].serial=="00:c3:18:d8:76:76:82:58:a6:96:ab:9d:d8:25:e2:7a:cd" or pe.signatures[i].serial=="c3:18:d8:76:76:82:58:a6:96:ab:9d:d8:25:e2:7a:cd") and 1615161600<=pe.signatures[i].not_after)
}
