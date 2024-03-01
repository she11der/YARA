import "pe"

rule REVERSINGLABS_Cert_Blocklist_D0312F9177Cd46B943Df3Ef22Db4608B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b36ba3c9-4a64-505a-ae27-ec8ee969dc29"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15114-L15132"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2eb955e91c927980cee031c6284e48bad315e891c32cdaf41b844090e841c44d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "United Systems Technology, Inc." and (pe.signatures[i].serial=="00:d0:31:2f:91:77:cd:46:b9:43:df:3e:f2:2d:b4:60:8b" or pe.signatures[i].serial=="d0:31:2f:91:77:cd:46:b9:43:df:3e:f2:2d:b4:60:8b") and 1341273600<=pe.signatures[i].not_after)
}
