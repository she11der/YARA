rule SIGNATURE_BASE_Casper_Included_Strings : FILE
{
	meta:
		description = "Casper French Espionage Malware - String Match in File - http://goo.gl/VRJNLo"
		author = "Florian Roth (Nextron Systems)"
		id = "34ba474d-0858-534a-8f32-db5a709e8814"
		date = "2015-03-06"
		modified = "2023-12-05"
		reference = "http://goo.gl/VRJNLo"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_casper.yar#L60-L83"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8796f45e459747db6bc08f362db7b152242f9f5bda3b72ddfc739cc9dcdfc55f"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$a0 = "cmd.exe /C FOR /L %%i IN (1,1,%d) DO IF EXIST"
		$a1 = "& SYSTEMINFO) ELSE EXIT"
		$c1 = "domcommon.exe" wide fullword
		$c2 = "jpic.gov.sy" fullword
		$c3 = "aiomgr.exe" wide fullword
		$c4 = "perfaudio.dat" fullword
		$c5 = "Casper_DLL.dll" fullword
		$c6 = { 7B 4B 59 DE 37 4A 42 26 59 98 63 C6 2D 0F 57 40 }
		$c7 = "{4216567A-4512-9825-7745F856}" fullword

	condition:
		all of ($a*) or uint16(0)==0x5a4d and (1 of ($c*))
}
