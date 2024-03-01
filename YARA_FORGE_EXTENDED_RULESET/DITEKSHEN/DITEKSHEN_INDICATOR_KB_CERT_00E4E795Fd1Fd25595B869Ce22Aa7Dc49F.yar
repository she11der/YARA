import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E4E795Fd1Fd25595B869Ce22Aa7Dc49F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8807c05d-c13b-58e8-9dda-c2eae6b5979c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6087-L6101"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "0aef5e2af3059597d218c544bc0b56078e1ef924af0530c62aa12679e0816410"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "269f25e6b7c690ae094086bd7825d03b48d4fcb1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OASIS COURT LIMITED" and (pe.signatures[i].serial=="00:e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f" or pe.signatures[i].serial=="e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f"))
}
