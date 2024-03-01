import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_Shredfilesteps : FILE
{
	meta:
		description = "Detects executables embedding/copying file shredding steps"
		author = "ditekSHen"
		id = "2a4ac767-8946-5e58-9087-aa1d3a97b5d5"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L2350-L2363"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9e784c1d06b232ac2de7318854a59b237aeb88d8e6670fe4ecc9f3230310088a"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = { 55 00 00 00 aa 00 00 00 92 49 24 00 49 24 92 00
                24 92 49 00 00 00 00 00 11 00 00 00 22 00 00 00
                33 00 00 00 44 00 00 00 66 00 00 00 88 00 00 00
                99 00 00 00 bb 00 00 00 cc 00 00 00 dd 00 00 00
                ee 00 00 00 ff 00 00 00 6d b6 db 00 b6 db 6d 00
                db 6d b6 }

	condition:
		uint16(0)==0x5a4d and all of them
}
