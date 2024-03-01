import "pe"

rule REVERSINGLABS_Cert_Blocklist_C04F5D17Af872Cb2C37E3367Fe761D0D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d7ef2bdf-afba-5254-bef2-78f4b6d5ecea"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4364-L4382"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4a4d60aa3722a710fe23d5e11c55a28bfe721bb4e797b041d58f62a994487799"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DES SP Z O O" and (pe.signatures[i].serial=="00:c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d" or pe.signatures[i].serial=="c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d") and 1594590024<=pe.signatures[i].not_after)
}
