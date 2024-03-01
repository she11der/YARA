import "pe"

rule REVERSINGLABS_Cert_Blocklist_6E889Bb3B7F7194B674C6A0335A608E0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d164846d-9552-5108-8b01-1b4b3e7c0b60"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12388-L12404"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fa2a47f4fb822089fcc958850ce516c8c5d95a6d9b575f3b1d1d4a2ceb2537e4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CLEVERCONTROL LLC" and pe.signatures[i].serial=="6e:88:9b:b3:b7:f7:19:4b:67:4c:6a:03:35:a6:08:e0" and 1646956800<=pe.signatures[i].not_after)
}
