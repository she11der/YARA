rule SIGNATURE_BASE_ACE_Containing_EXE
{
	meta:
		description = "Looks for ACE Archives containing an exe/scr file"
		author = "Florian Roth (Nextron Systems) - based on Nick Hoffman' rule - Morphick Inc"
		id = "0756f0e7-39f1-572d-a77d-1f7826332360"
		date = "2015-09-09"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_ace_with_exe.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "27fba0db7a98fbaf4b3710a9e411ed74860099c133a2e83ddf368ae2fef3c288"
		score = 50
		quality = 83
		tags = ""

	strings:
		$header = { 2a 2a 41 43 45 2a 2a }
		$extensions1 = ".exe"
		$extensions2 = ".EXE"
		$extensions3 = ".scr"
		$extensions4 = ".SCR"

	condition:
		$header at 7 and for any of ($extensions*) : ($ in (81..(81+ uint16(79))))
}
