import "pe"

rule REVERSINGLABS_Cert_Blocklist_332Bd5801E8415585E72C87E0E2Ec71D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d251afda-7582-5a00-a100-fd3acff2f995"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11384-L11400"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3648c3a8dbcdbd24746b9fa8cb3071d5f5019e5917848d88437158c6cb165445"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Elite Marketing Strategies, Inc." and pe.signatures[i].serial=="33:2b:d5:80:1e:84:15:58:5e:72:c8:7e:0e:2e:c7:1d" and 1662616824<=pe.signatures[i].not_after)
}
