rule SIGNATURE_BASE_Trojandownloader : FILE
{
	meta:
		description = "Trojan Downloader - Flash Exploit Feb15"
		author = "Florian Roth (Nextron Systems)"
		id = "d61f59ef-31a3-5e52-9525-61910bb150db"
		date = "2015-02-11"
		modified = "2023-12-05"
		reference = "http://goo.gl/wJ8V1I"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_malware_generic.yar#L4-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5b8d4280ff6fc9c8e1b9593cbaeb04a29e64a81e"
		logic_hash = "4911098beea1d348d41d6a38c03b343bb7b8a8090ba664fd4b0747045127c686"
		score = 60
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "Hello World!" fullword ascii
		$x2 = "CONIN$" fullword ascii
		$s6 = "GetCommandLineA" fullword ascii
		$s7 = "ExitProcess" fullword ascii
		$s8 = "CreateFileA" fullword ascii
		$s5 = "SetConsoleMode" fullword ascii
		$s9 = "TerminateProcess" fullword ascii
		$s10 = "GetCurrentProcess" fullword ascii
		$s11 = "UnhandledExceptionFilter" fullword ascii
		$s3 = "user32.dll" fullword ascii
		$s16 = "GetEnvironmentStrings" fullword ascii
		$s2 = "GetLastActivePopup" fullword ascii
		$s17 = "GetFileType" fullword ascii
		$s19 = "HeapCreate" fullword ascii
		$s20 = "VirtualFree" fullword ascii
		$s21 = "WriteFile" fullword ascii
		$s22 = "GetOEMCP" fullword ascii
		$s23 = "VirtualAlloc" fullword ascii
		$s24 = "GetProcAddress" fullword ascii
		$s26 = "FlushFileBuffers" fullword ascii
		$s27 = "SetStdHandle" fullword ascii
		$s28 = "KERNEL32.dll" fullword ascii

	condition:
		$x1 and $x2 and ( all of ($s*)) and filesize <35000
}
