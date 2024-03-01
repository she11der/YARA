import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Ef6392B2993A6F67578299659467Ea8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "123e5aed-0ef4-5146-81bb-5d455a9cf92e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9534-L9550"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f6b454a575ea7635d5edebffe3c9c83e95312ee33245e733987532348258733e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALUSEN d. o. o." and pe.signatures[i].serial=="1e:f6:39:2b:29:93:a6:f6:75:78:29:96:59:46:7e:a8" and 1618531200<=pe.signatures[i].not_after)
}
