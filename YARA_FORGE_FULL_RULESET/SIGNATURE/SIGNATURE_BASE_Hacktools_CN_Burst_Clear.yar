import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Burst_Clear
{
	meta:
		description = "Disclosed hacktool set - file Clear.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "21f33a36-779e-5eac-819c-ef79f291b43c"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1398-L1419"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "148c574a4e6e661aeadaf3a4c9eafa92a00b68e4"
		logic_hash = "d10ed2c6ea3f1a8b289529cc90f50f84288003576aced903f48db3c2abc4722d"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "del /f /s /q %systemdrive%\\*.log    " fullword ascii
		$s1 = "del /f /s /q %windir%\\*.bak    " fullword ascii
		$s4 = "del /f /s /q %systemdrive%\\*.chk    " fullword ascii
		$s5 = "del /f /s /q %systemdrive%\\*.tmp    " fullword ascii
		$s8 = "del /f /q %userprofile%\\COOKIES s\\*.*    " fullword ascii
		$s9 = "rd /s /q %windir%\\temp & md %windir%\\temp    " fullword ascii
		$s11 = "del /f /s /q %systemdrive%\\recycled\\*.*    " fullword ascii
		$s12 = "del /f /s /q \"%userprofile%\\Local Settings\\Temp\\*.*\"    " fullword ascii
		$s19 = "del /f /s /q \"%userprofile%\\Local Settings\\Temporary Internet Files\\*.*\"   " ascii

	condition:
		5 of them
}
