import "pe"

rule REVERSINGLABS_Cert_Blocklist_Aeba4C39306Fdd022849867801645814 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f8cb78cf-541c-5038-b7af-83679c978ec8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3958-L3976"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "82c149f1d8ef93a0df2035690c5cdca935236687bc36a35a84c3d6610eb6902c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SK AI MAS GmbH" and (pe.signatures[i].serial=="00:ae:ba:4c:39:30:6f:dd:02:28:49:86:78:01:64:58:14" or pe.signatures[i].serial=="ae:ba:4c:39:30:6f:dd:02:28:49:86:78:01:64:58:14") and 1579478400<=pe.signatures[i].not_after)
}
