import "pe"

rule REVERSINGLABS_Cert_Blocklist_54C793D2224Bdd6Ca527Bb2B7B9Dfe9D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "80e92980-f4eb-5ac2-9f68-14c352758791"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11706-L11722"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "81c9c1d841d4aae3de229cc499ee84920d89928590a3eb157f7a7a7fbc46b4a8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CODE - HANDLE, s. r. o." and pe.signatures[i].serial=="54:c7:93:d2:22:4b:dd:6c:a5:27:bb:2b:7b:9d:fe:9d" and 1629676800<=pe.signatures[i].not_after)
}
