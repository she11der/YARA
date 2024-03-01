import "pe"

rule REVERSINGLABS_Cert_Blocklist_34D42E871Ddb1C92Fa20B55B384E1259 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "98a8f4b0-08d0-5e09-b46e-74b46f4df223"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11650-L11666"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8af5f4abe6425713b7c1fd17deaa78b2cfd6ef73ad960bce883e95661c2dbb56"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VENS CORP" and pe.signatures[i].serial=="34:d4:2e:87:1d:db:1c:92:fa:20:b5:5b:38:4e:12:59" and 1630368000<=pe.signatures[i].not_after)
}
