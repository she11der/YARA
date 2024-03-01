import "pe"

rule REVERSINGLABS_Cert_Blocklist_9Bd81A9Adaf71F1Ff081C1F4A05D7Fd7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "727167de-5678-558d-b948-8a40839d0500"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11516-L11534"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e275a1fd2eb931030fa8b5fc11cd1b335835aaa553a42455053cb93fef5e6e72"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SMART TOYS AND GAMES, INC" and (pe.signatures[i].serial=="00:9b:d8:1a:9a:da:f7:1f:1f:f0:81:c1:f4:a0:5d:7f:d7" or pe.signatures[i].serial=="9b:d8:1a:9a:da:f7:1f:1f:f0:81:c1:f4:a0:5d:7f:d7") and 1601683200<=pe.signatures[i].not_after)
}
