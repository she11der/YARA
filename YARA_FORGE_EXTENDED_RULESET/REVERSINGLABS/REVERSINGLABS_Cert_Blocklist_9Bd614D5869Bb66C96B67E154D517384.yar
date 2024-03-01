import "pe"

rule REVERSINGLABS_Cert_Blocklist_9Bd614D5869Bb66C96B67E154D517384 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "eb42b516-aac6-5bee-af1d-70e0e66700f5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3752-L3770"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d9eea38a1340797cef129b12cf2bb46c444e6f312db7356260f0ac0d9e63183d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\"CENTR MBP\"" and (pe.signatures[i].serial=="00:9b:d6:14:d5:86:9b:b6:6c:96:b6:7e:15:4d:51:73:84" or pe.signatures[i].serial=="9b:d6:14:d5:86:9b:b6:6c:96:b6:7e:15:4d:51:73:84") and 1581618180<=pe.signatures[i].not_after)
}
