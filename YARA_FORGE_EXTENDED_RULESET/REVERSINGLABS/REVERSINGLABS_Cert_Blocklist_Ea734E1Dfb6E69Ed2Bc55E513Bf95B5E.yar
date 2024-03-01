import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ea734E1Dfb6E69Ed2Bc55E513Bf95B5E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8e059a2a-c436-5247-b395-a2f594c1c9a9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9860-L9878"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a18d1c1e5e22c1aa041a4b2d23d2aefcbedbd3517a079d578e1a143ecadb4533"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Postmarket LLC" and (pe.signatures[i].serial=="00:ea:73:4e:1d:fb:6e:69:ed:2b:c5:5e:51:3b:f9:5b:5e" or pe.signatures[i].serial=="ea:73:4e:1d:fb:6e:69:ed:2b:c5:5e:51:3b:f9:5b:5e") and 1635153791<=pe.signatures[i].not_after)
}
