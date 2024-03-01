import "pe"

rule REVERSINGLABS_Cert_Blocklist_A9C1523Cb2C73A82771D318124963E87 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b21365d0-eaff-51da-8b8e-6a6ee75a5b95"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13818-L13836"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "87e314d14361f56935b7a8fb93468cfaf2c73e16c25d68a61ec80ad9334d3115"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ULTERA" and (pe.signatures[i].serial=="00:a9:c1:52:3c:b2:c7:3a:82:77:1d:31:81:24:96:3e:87" or pe.signatures[i].serial=="a9:c1:52:3c:b2:c7:3a:82:77:1d:31:81:24:96:3e:87") and 1499731200<=pe.signatures[i].not_after)
}
