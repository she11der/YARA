rule SIGNATURE_BASE_Win7Elevatev2 : FILE
{
	meta:
		description = "Detects Win7Elevate - Windows UAC bypass utility"
		author = "Florian Roth (Nextron Systems)"
		id = "af092d16-ca95-5985-822a-50457c9cbcc9"
		date = "2015-05-14"
		modified = "2023-12-05"
		reference = "http://www.pretentiousname.com/misc/W7E_Source/Win7Elevate_Inject.cpp.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/exploit_uac_elevators.yar#L2-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2f5859388c6074f1a75f0c40387f30ffa50d6b87f20f518fd1af7398c95cd650"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4f53ff6a04e46eda92b403faf42219a545c06c29"
		hash2 = "808d04c187a524db402c5b2be17ce799d2654bd1"

	strings:
		$x1 = "This program attempts to bypass Windows 7's default UAC settings to run " wide
		$x2 = "Win7ElevateV2\\x64\\Release\\" ascii
		$x3 = "Run the command normally (without code injection)" wide
		$x4 = "Inject file copy && elevate command" fullword wide
		$x5 = "http://www.pretentiousname.com/misc/win7_uac_whitelist2.html" fullword wide
		$x6 = "For injection, pick any unelevated Windows process with ASLR on:" fullword wide
		$s1 = "\\cmd.exe" wide
		$s2 = "runas" wide
		$s3 = "explorer.exe" wide
		$s4 = "Couldn't load kernel32.dll" wide
		$s5 = "CRYPTBASE.dll" wide
		$s6 = "shell32.dll" wide
		$s7 = "ShellExecuteEx" ascii
		$s8 = "COMCTL32.dll" ascii
		$s9 = "ShellExecuteEx" ascii
		$s10 = "HeapAlloc" ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) or all of ($s*))
}
