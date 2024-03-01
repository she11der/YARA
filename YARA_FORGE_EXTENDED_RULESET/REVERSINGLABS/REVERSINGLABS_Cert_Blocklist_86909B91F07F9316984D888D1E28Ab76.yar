import "pe"

rule REVERSINGLABS_Cert_Blocklist_86909B91F07F9316984D888D1E28Ab76 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3cde0016-14d8-5b3a-860e-f5128f899542"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8452-L8470"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "abd84492ed008125688a53e20d51780fa0b8c2309dcf751ff76a03d6f337beaa"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dantherm Intelligent Monitoring A/S" and (pe.signatures[i].serial=="00:86:90:9b:91:f0:7f:93:16:98:4d:88:8d:1e:28:ab:76" or pe.signatures[i].serial=="86:90:9b:91:f0:7f:93:16:98:4d:88:8d:1e:28:ab:76") and 1611273600<=pe.signatures[i].not_after)
}
