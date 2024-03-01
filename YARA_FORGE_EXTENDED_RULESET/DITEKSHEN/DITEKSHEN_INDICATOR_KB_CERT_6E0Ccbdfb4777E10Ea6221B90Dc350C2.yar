import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6E0Ccbdfb4777E10Ea6221B90Dc350C2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c8f66f21-db29-5a5d-a74d-58c152a17bc3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2469-L2480"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "fee9662133f0a3d88ce97c27f150bcea8faf21b4c4b97f90bb2aae73ee332bb9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "367b3092fbcd132efdbebabdc7240e29e3c91366f78137a27177315d32a926b9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TRAUMALAB INTERNATIONAL APS" and pe.signatures[i].serial=="6e:0c:cb:df:b4:77:7e:10:ea:62:21:b9:0d:c3:50:c2")
}
