import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_References_Sectools_B64Encoded : FILE
{
	meta:
		description = "Detects executables referencing many base64-encoded IR and analysis tools names"
		author = "ditekSHen"
		id = "2d3c994a-5b7c-52c5-a4a1-e67a773b692b"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L897-L941"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "20f889c9c50e8c5e55fd7ebe508015b1e72e6f7ef1b410e5e707d554fb8e8588"
		score = 40
		quality = 43
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "VGFza21ncg==" ascii wide
		$s2 = "dGFza21ncg==" ascii wide
		$s3 = "UHJvY2Vzc0hhY2tlcg" ascii wide
		$s4 = "cHJvY2V4cA" ascii wide
		$s5 = "cHJvY2V4cDY0" ascii wide
		$s6 = "aHR0cCBhbmFseXplci" ascii wide
		$s7 = "ZmlkZGxlcg" ascii wide
		$s8 = "ZWZmZXRlY2ggaHR0cCBzbmlmZmVy" ascii wide
		$s9 = "ZmlyZXNoZWVw" ascii wide
		$s10 = "SUVXYXRjaCBQcm9mZXNzaW9uYWw" ascii wide
		$s11 = "ZHVtcGNhcA" ascii wide
		$s12 = "d2lyZXNoYXJr" ascii wide
		$s13 = "c3lzaW50ZXJuYWxzIHRjcHZpZXc" ascii wide
		$s14 = "TmV0d29ya01pbmVy" ascii wide
		$s15 = "TmV0d29ya1RyYWZmaWNWaWV3" ascii wide
		$s16 = "SFRUUE5ldHdvcmtTbmlmZmVy" ascii wide
		$s17 = "dGNwZHVtcA" ascii wide
		$s18 = "aW50ZXJjZXB0ZXI" ascii wide
		$s19 = "SW50ZXJjZXB0ZXItTkc" ascii wide
		$s20 = "b2xseWRiZw" ascii wide
		$s21 = "eDY0ZGJn" ascii wide
		$s22 = "eDMyZGJn" ascii wide
		$s23 = "ZG5zcHk" ascii wide
		$s24 = "ZGU0ZG90" ascii wide
		$s25 = "aWxzcHk" ascii wide
		$s26 = "ZG90cGVla" ascii wide
		$s27 = "aWRhNjQ" ascii wide
		$s28 = "UkRHIFBhY2tlciBEZXRlY3Rvcg" ascii wide
		$s29 = "Q0ZGIEV4cGxvcmVy" ascii wide
		$s30 = "UEVpRA" ascii wide
		$s31 = "cHJvdGVjdGlvbl9pZA" ascii wide
		$s32 = "TG9yZFBF" ascii wide
		$s33 = "cGUtc2lldmU=" ascii wide
		$s34 = "TWVnYUR1bXBlcg" ascii wide
		$s35 = "VW5Db25mdXNlckV4" ascii wide
		$s36 = "VW5pdmVyc2FsX0ZpeGVy" ascii wide
		$s37 = "Tm9GdXNlckV4" ascii wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
