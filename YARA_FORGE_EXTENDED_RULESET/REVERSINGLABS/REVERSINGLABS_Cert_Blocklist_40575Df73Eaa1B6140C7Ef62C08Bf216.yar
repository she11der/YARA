import "pe"

rule REVERSINGLABS_Cert_Blocklist_40575Df73Eaa1B6140C7Ef62C08Bf216 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6a6e6320-8e01-5ec7-8119-3e90f1eacc4e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L243-L259"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7da8e98f38413e5cbb18e3c7771c530afb766dd9fbeb8fdd2264617aff24f920"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dali Feifang Tech Co.,LTD." and pe.signatures[i].serial=="40:57:5d:f7:3e:aa:1b:61:40:c7:ef:62:c0:8b:f2:16" and 1394063999<=pe.signatures[i].not_after)
}
