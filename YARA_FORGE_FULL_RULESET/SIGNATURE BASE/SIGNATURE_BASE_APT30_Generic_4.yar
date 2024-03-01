rule SIGNATURE_BASE_APT30_Generic_4 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "2b246ae2-ec7d-5813-913e-729e4192da59"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L1110-L1140"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d6a45baee2741c5ebb05fc3f17974a041cd37f665df1e67934b0928fc75f37c3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "bb390f99bfde234bbed59f6a0d962ba874b2396c"
		hash1 = "b47e20ac5889700438dc241f28f4e224070810d2"
		hash2 = "a9a50673ac000a313f3ddba55d63d9773b9f4143"
		hash3 = "ac96d7f5957aef09bd983465c497de24c6d17a92"

	strings:
		$s0 = "del NetEagle_Scout.bat" fullword
		$s1 = "NetEagle_Scout.bat" fullword
		$s2 = "\\visit.exe"
		$s3 = "\\System.exe"
		$s4 = "\\System.dat"
		$s5 = "\\ieupdate.exe"
		$s6 = "GOTO ERROR" fullword
		$s7 = ":ERROR" fullword
		$s9 = "IF EXIST " fullword
		$s10 = "ioiocn" fullword
		$s11 = "SetFileAttribute" fullword
		$s12 = "le_0*^il" fullword
		$s13 = "le_.*^il" fullword
		$s14 = "le_-*^il" fullword

	condition:
		filesize <250KB and uint16(0)==0x5A4D and all of them
}
