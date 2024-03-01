rule SIGNATURE_BASE_APT30_Generic_8 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "a6845222-0a3e-5327-a448-36e8d54362a5"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L1207-L1232"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "2c240d2a35ce3d621d108d03d4e720ddf86e248047fb4dd7f9724e64020caa7f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "b47e20ac5889700438dc241f28f4e224070810d2"
		hash1 = "a9a50673ac000a313f3ddba55d63d9773b9f4143"
		hash2 = "ac96d7f5957aef09bd983465c497de24c6d17a92"

	strings:
		$s0 = "Windows NT4.0" fullword
		$s1 = "Windows NT3.51" fullword
		$s2 = "%d;%d;%d;%ld;%ld;%ld;" fullword
		$s3 = "%s %d.%d Build%d %s" fullword
		$s4 = "MSAFD Tcpip [TCP/IP]" fullword
		$s5 = "SQSRSS" fullword
		$s8 = "WM_COMP" fullword
		$s9 = "WM_MBU" fullword
		$s11 = "WM_GRID" fullword
		$s12 = "WM_RBU" fullword

	condition:
		filesize <250KB and uint16(0)==0x5A4D and all of them
}
