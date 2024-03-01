import "pe"

rule REVERSINGLABS_Cert_Blocklist_0A82Bd1E144E8814D75B1A5527Bebf3E : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "f3d7d714-8085-524a-814c-ab8cc59ceb4f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L927-L943"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2534e58ce1e5adbb10dbacb664d40cc32faec341bdb93b926cc85b666cc7b77e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DigiNotar Root CA G2" and pe.signatures[i].serial=="0a:82:bd:1e:14:4e:88:14:d7:5b:1a:55:27:be:bf:3e" and 1308182400<=pe.signatures[i].not_after)
}
