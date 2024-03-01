import "pe"

rule REVERSINGLABS_Cert_Blocklist_1F2E8Effbb08C7Dbcc7A7F2D835457B5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "cf032593-e742-56d5-a579-3f38a31e2c0c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3940-L3956"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0b446641617d435c3d312592957e19c3d391b0149eafcf9ac2da51e8d9080eb4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RTI, OOO" and pe.signatures[i].serial=="1f:2e:8e:ff:bb:08:c7:db:cc:7a:7f:2d:83:54:57:b5" and 1581382360<=pe.signatures[i].not_after)
}
