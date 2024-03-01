rule SIGNATURE_BASE_Hxdef100
{
	meta:
		description = "Webshells Auto-generated - file hxdef100.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "fb376c18-02d2-5866-a0e2-ccb5262091dd"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8156-L8169"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "55cc1769cef44910bd91b7b73dee1f6c"
		logic_hash = "a2002dcddad7ffdbe9614723163016f9357347bb704640d3933ce4513c37d474"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "RtlAnsiStringToUnicodeString"
		$s8 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
		$s9 = "\\\\.\\mailslot\\hxdef-rk100sABCDEFGH"

	condition:
		all of them
}
