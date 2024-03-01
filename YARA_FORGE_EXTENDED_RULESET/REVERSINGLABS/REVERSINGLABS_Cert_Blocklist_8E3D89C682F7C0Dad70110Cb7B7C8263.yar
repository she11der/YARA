import "pe"

rule REVERSINGLABS_Cert_Blocklist_8E3D89C682F7C0Dad70110Cb7B7C8263 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1adc776c-1549-5149-bd2f-81920a8d7255"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5712-L5730"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a0f42c5492469e7f132b000aead2d674fed4ea9c0e168579fd55a6c89b45ae4d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "WORK PLACEMENTS INTERNATIONAL LIMITED" and (pe.signatures[i].serial=="00:8e:3d:89:c6:82:f7:c0:da:d7:01:10:cb:7b:7c:82:63" or pe.signatures[i].serial=="8e:3d:89:c6:82:f7:c0:da:d7:01:10:cb:7b:7c:82:63") and 1570626662<=pe.signatures[i].not_after)
}
