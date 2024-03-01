import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_References_Passwordmanagers : FILE
{
	meta:
		description = "Detects executables referencing many Password Manager software clients. Observed in infostealers"
		author = "ditekSHen"
		id = "4da7bf22-fdd7-53b7-bdfc-da7ac5657f6f"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L2086-L2097"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "6d2f7739282611166a7e06d96345c46df92500b387d9f940169d5ee6664ea5ad"
		score = 40
		quality = 37
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "1Password\\" ascii wide nocase
		$s2 = "Dashlane\\" ascii wide nocase
		$s3 = "nordpass*.sqlite" ascii wide nocase
		$s4 = "RoboForm\\" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 3 of them
}
