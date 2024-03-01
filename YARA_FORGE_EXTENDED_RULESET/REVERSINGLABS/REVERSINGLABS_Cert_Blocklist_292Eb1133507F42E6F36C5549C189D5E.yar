import "pe"

rule REVERSINGLABS_Cert_Blocklist_292Eb1133507F42E6F36C5549C189D5E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b557864d-c573-5789-9959-8df3036d5ac5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9996-L10012"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bc3ef217455b74900cae114d25b02325d2bef25c11873342df1dd2369cbce76a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Affairs-case s.r.o." and pe.signatures[i].serial=="29:2e:b1:13:35:07:f4:2e:6f:36:c5:54:9c:18:9d:5e" and 1638832273<=pe.signatures[i].not_after)
}
