import "pe"

rule REVERSINGLABS_Cert_Blocklist_02F17566Ef568Dc06C9A379Ea2F4Faea : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "a14e16ff-844c-53ff-9297-8760265da747"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2284-L2300"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e3ec8a6de817354862880301e78a999f45f02c2fa8512bba6d27c9776f1a3417"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VALERIANO BEDESCHI" and pe.signatures[i].serial=="02:f1:75:66:ef:56:8d:c0:6c:9a:37:9e:a2:f4:fa:ea" and 1441324799<=pe.signatures[i].not_after)
}
