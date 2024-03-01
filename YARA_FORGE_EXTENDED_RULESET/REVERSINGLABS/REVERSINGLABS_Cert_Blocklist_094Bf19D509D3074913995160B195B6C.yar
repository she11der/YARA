import "pe"

rule REVERSINGLABS_Cert_Blocklist_094Bf19D509D3074913995160B195B6C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8241e2c6-e4e7-581c-b759-6314d2e28a4d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L441-L457"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3c1ed012716f36876d9375838befb9821b87cafc6aca57a0f18392f80f5ba325"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Porral Twinware S.L.L." and pe.signatures[i].serial=="09:4b:f1:9d:50:9d:30:74:91:39:95:16:0b:19:5b:6c" and 1373241599<=pe.signatures[i].not_after)
}
