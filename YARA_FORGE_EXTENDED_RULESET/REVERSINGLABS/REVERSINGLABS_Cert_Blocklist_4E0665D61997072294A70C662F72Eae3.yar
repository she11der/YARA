import "pe"

rule REVERSINGLABS_Cert_Blocklist_4E0665D61997072294A70C662F72Eae3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1370a3b5-a254-5197-ac85-5b33e8d9fa38"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15936-L15952"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f07cdfd522db0a92fe1dba30f158b2c89bb5424bdcdfda50ae42fcfddeac19ba"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yuanyuan Zhang" and pe.signatures[i].serial=="4e:06:65:d6:19:97:07:22:94:a7:0c:66:2f:72:ea:e3" and 1474502400<=pe.signatures[i].not_after)
}
