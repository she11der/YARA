import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00C2Fc83D458E653837Fcfc132C9B03062 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "fbc9420d-4670-502f-af6a-13d17fb73938"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2352-L2363"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "96ed5e78195f12cdc0316ed454ad4e2235253ed897905c4a97756b306933d874"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "82294a7efa5208eb2344db420b9aeff317337a073c1a6b41b39dda549a94557e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Vertical" and pe.signatures[i].serial=="00:c2:fc:83:d4:58:e6:53:83:7f:cf:c1:32:c9:b0:30:62")
}
