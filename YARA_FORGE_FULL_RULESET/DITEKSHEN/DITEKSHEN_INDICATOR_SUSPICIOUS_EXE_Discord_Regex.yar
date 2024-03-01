import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Discord_Regex : FILE
{
	meta:
		description = "Detects executables referencing Discord tokens regular expressions"
		author = "ditekSHen"
		id = "4c508cae-bb25-549b-8f35-a6a22928a9a3"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1888-L1896"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b6be1dd8e25311442a59ee2afbd99f6e9663dd06919c07269b76238af0bbd5f2"
		score = 40
		quality = 43
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_\\-]{27}|mfa\\.[a-zA-Z0-9_\\-]{84}" ascii wide nocase

	condition:
		( uint16(0)==0x5a4d and all of them ) or all of them
}
