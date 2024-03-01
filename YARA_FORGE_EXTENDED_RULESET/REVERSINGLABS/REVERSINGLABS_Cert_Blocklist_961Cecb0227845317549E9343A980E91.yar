import "pe"

rule REVERSINGLABS_Cert_Blocklist_961Cecb0227845317549E9343A980E91 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f319592a-5f08-5f2c-b840-5f897695e054"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9514-L9532"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c74512e95e2d6aedecb1dbd30fac6fde40d1e9520c89b785519694d9bc9ba854"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AmiraCo Oy" and (pe.signatures[i].serial=="00:96:1c:ec:b0:22:78:45:31:75:49:e9:34:3a:98:0e:91" or pe.signatures[i].serial=="96:1c:ec:b0:22:78:45:31:75:49:e9:34:3a:98:0e:91") and 1615248000<=pe.signatures[i].not_after)
}
