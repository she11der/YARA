import "pe"

rule REVERSINGLABS_Cert_Blocklist_7C7Fc3616F3157A28F702Cc1Df275Dcd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "78d2adb9-fc1c-5f48-80cb-3f1bd12b6ba5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14950-L14966"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c2dcea21c7a3e3aef6408f11c23edbce6d8f655f298654552a607a9b0caabb28"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CFES Projects Ltd" and pe.signatures[i].serial=="7c:7f:c3:61:6f:31:57:a2:8f:70:2c:c1:df:27:5d:cd" and 1522972800<=pe.signatures[i].not_after)
}
