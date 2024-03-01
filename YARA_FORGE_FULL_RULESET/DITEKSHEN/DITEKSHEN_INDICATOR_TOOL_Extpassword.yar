import "pe"

rule DITEKSHEN_INDICATOR_TOOL_Extpassword : FILE
{
	meta:
		description = "Detects ExtPassword External Drive Password Recovery"
		author = "ditekSHen"
		id = "bb06d2c1-964d-5a3d-a741-09b8ef5ac7fa"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L1387-L1403"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "525530cb7e9f44be0408fd710306f90056b1b6b9a9e4779d8c1eb1ddef443fb0"
		score = 75
		quality = 50
		tags = "FILE"

	strings:
		$x1 = "ExtPassword!" fullword wide
		$s2 = "GReading Chrome password file: %s" fullword wide
		$s3 = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy%d" fullword wide
		$s4 = "2015-07-27 13:49:41 b8e92227a469de677a66da62e4361f099c0b79d0" ascii
		$s5 = "metadata WHERE id = 'password'" ascii
		$s6 = /Scanning\s(Credentials\sfolder|Credentials\sfolder|Firefox\sand\sother\sMozilla\sWeb\sbrowsers|Chromium-based\Web\browsers|Outlook\saccounts|Windows\sVault|dialup\/VPN\sitems|wireless\skeys|Windows\ssecurity\squestions|vault\spasswords)/ wide
		$s7 = "lhelp32Snapsho" fullword ascii
		$s8 = "SELECT origin_" fullword ascii
		$s9 = "password#Ck" fullword ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) and 3 of ($s*)) or 6 of ($s*)
}
