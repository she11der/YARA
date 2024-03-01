import "pe"

rule REVERSINGLABS_Cert_Blocklist_32Bc299F0694C19Ec21E71265B1D7E17 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fa2302c3-4002-5bf0-812b-45298abbda8d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13746-L13762"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cb522e3084d382c451a8b040095e75582675f90dbb588e370f2f0054f4c2d14b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="32:bc:29:9f:06:94:c1:9e:c2:1e:71:26:5b:1d:7e:17" and 1474416000<=pe.signatures[i].not_after)
}
