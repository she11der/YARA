import "pe"

rule REVERSINGLABS_Cert_Blocklist_2E36360538624C9B1Afd78A2Fb756028 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "549a566b-0c94-516c-9231-a5e54136785f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8824-L8840"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9cbb50c7d383048fd506506fa9ee8bf7c6d82feaf21bcde4008ab99b82e234a7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ts Trade ApS" and pe.signatures[i].serial=="2e:36:36:05:38:62:4c:9b:1a:fd:78:a2:fb:75:60:28" and 1615766400<=pe.signatures[i].not_after)
}
