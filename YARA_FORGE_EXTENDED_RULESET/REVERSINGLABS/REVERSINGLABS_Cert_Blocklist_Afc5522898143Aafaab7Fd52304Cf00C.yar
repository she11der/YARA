import "pe"

rule REVERSINGLABS_Cert_Blocklist_Afc5522898143Aafaab7Fd52304Cf00C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "016ad027-bd6a-58e0-9099-341b81dd6f70"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8922-L8940"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bfcf2fbbd9be97202eeb44c0f81f0a0713d4d30c466f2b170231c7f9df0e9e6d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "YAN CHING LIMITED" and (pe.signatures[i].serial=="00:af:c5:52:28:98:14:3a:af:aa:b7:fd:52:30:4c:f0:0c" or pe.signatures[i].serial=="af:c5:52:28:98:14:3a:af:aa:b7:fd:52:30:4c:f0:0c") and 1622419200<=pe.signatures[i].not_after)
}
