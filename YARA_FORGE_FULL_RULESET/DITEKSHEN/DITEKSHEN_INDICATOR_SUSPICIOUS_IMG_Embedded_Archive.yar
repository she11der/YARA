import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_IMG_Embedded_Archive : FILE
{
	meta:
		description = "Detects images embedding archives. Observed in TheRat RAT."
		author = "ditekSHen"
		id = "2c8e15dc-2e84-5f9b-b538-cba204a3d38c"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L45-L66"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0e61bc2489a54047c66a659ae2cb6df66683845676e1c02c34d9a0987ddec4bb"
		score = 40
		quality = 37
		tags = "FILE"
		importance = 20

	strings:
		$sevenzip1 = { 37 7a bc af 27 1c 00 04 }
		$sevenzip2 = { 37 e4 53 96 c9 db d6 07 }
		$zipwopass = { 50 4b 03 04 14 00 00 00 }
		$zipwipass = { 50 4b 03 04 33 00 01 00 }
		$zippkfile = { 50 4b 03 04 0a 00 02 00 }
		$rarheade1 = { 52 61 72 21 1a 07 01 00 }
		$rarheade2 = { 52 65 74 75 72 6e 2d 50 }
		$rarheade3 = { 52 61 72 21 1a 07 00 cf }
		$mscabinet = { 4d 53 46 54 02 00 01 00 }
		$zlockproe = { 50 4b 03 04 14 00 01 00 }
		$winzip = { 57 69 6E 5A 69 70 }
		$pklite = { 50 4B 4C 49 54 45 }
		$pksfx = { 50 4B 53 70 58 }

	condition:
		( uint32(0)==0xe0ffd8ff or uint32(0)==0x474e5089 or uint16(0)==0x4d42) and 1 of them
}
