import "pe"

rule REVERSINGLABS_Cert_Blocklist_7D3250B27E0547C77307030491B42802 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "54073485-e9a5-5a0b-a907-0e8a528da85d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1198-L1214"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "65f036921dfb9cbce3275aefb7111711e50874440096b2e3c3b55190cfc14ddb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Banco do Brasil S.A." and pe.signatures[i].serial=="7d:32:50:b2:7e:05:47:c7:73:07:03:04:91:b4:28:02" and 1412207999<=pe.signatures[i].not_after)
}
