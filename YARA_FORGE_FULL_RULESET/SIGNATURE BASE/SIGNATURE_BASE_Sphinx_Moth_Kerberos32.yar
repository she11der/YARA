rule SIGNATURE_BASE_Sphinx_Moth_Kerberos32 : FILE
{
	meta:
		description = "sphinx moth threat group file kerberos32.dll"
		author = "Kudelski Security - Nagravision SA (modified by Florian Roth)"
		id = "769ee362-2363-511a-8f17-99e66c9bab53"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "www.kudelskisecurity.com"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sphinx_moth.yar#L61-L85"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5b672c9b9b0ffffd8f243832ea217bfc10b08026c71d297ee1047ca999fb829c"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "%WINDIR%\\ativpsrz.bin" fullword ascii
		$x2 = "%WINDIR%\\ativpsrn.bin" fullword ascii
		$x3 = "kerberos32.dll" fullword wide
		$x4 = "KERBEROS64.dll" fullword ascii
		$x5 = "kerberos%d.dll" fullword ascii
		$s1 = "\\\\.\\pipe\\lsassp" fullword ascii
		$s2 = "LSASS secure pipe" fullword ascii
		$s3 = "NullSessionPipes" fullword ascii
		$s4 = "getlog" fullword ascii
		$s5 = "startlog" fullword ascii
		$s6 = "stoplog" fullword ascii
		$s7 = "Unsupported OS (%d)" fullword ascii
		$s8 = "Unsupported OS (%s)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (2 of ($x*) or all of ($s*))
}
